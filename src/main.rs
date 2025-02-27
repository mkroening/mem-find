use std::ffi::CStr;
use std::fmt::{self, Write};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::ops::Range;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::process::ExitCode;
use std::str::{self, FromStr};

use clap::Parser;
use libc::{ino_t, pid_t};
use memchr::memmem;
use nix::unistd::{Uid, User};

/// Searches the memory of a process (haystack) for a string (needle).
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Print the memory maps while searching through them.
    #[arg(short, long)]
    verbose: bool,

    /// The string to search for.
    needle: String,

    /// The PID of the process to search.
    pid: Vec<pid_t>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    args.run()
}

impl Args {
    fn run(&self) -> ExitCode {
        let mut success = true;

        for pid in self.pid.iter().copied() {
            if let Err(err) = find(self.verbose, &self.needle, pid) {
                eprintln!("{err}");
                success = false;
            }
        }

        if success {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

fn find(verbose: bool, needle: &str, pid: pid_t) -> io::Result<()> {
    let mut cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline"))?;
    for i in 0..cmdline.len() {
        if cmdline.as_bytes()[i] == b'\0' {
            cmdline.replace_range(i..=i, " ");
        }
    }
    cmdline.pop();

    let metadata = fs::metadata(format!("/proc/{pid}"))?;
    let user = User::from_uid(Uid::from_raw(metadata.uid()))?.unwrap();
    let name = &user.name;

    eprintln!("Searching for {needle:?} in process {pid} by {name}: `{cmdline}`");

    let maps = File::open(format!("/proc/{pid}/maps"))?;
    let maps = BufReader::new(maps);

    let mem_path = format!("/proc/{pid}/mem");
    let mem = File::open(&mem_path)?;

    let finder = memmem::Finder::new(needle);
    for map in maps.lines() {
        let map = map?;
        let map = match map.parse::<Map>() {
            Ok(map) => map,
            Err(err) => {
                eprintln!("could not parse map: {map} ({err:?})");
                continue;
            }
        };

        if !map.perms.read {
            continue;
        }

        if map.pathname == "[vvar]" {
            continue;
        }

        if verbose {
            eprintln!("{map}");
        }

        let mut haystack = vec![0; map.address.end - map.address.start];

        if let Err(err) = mem.read_exact_at(&mut haystack, map.address.start as u64) {
            eprintln!("could not read {mem_path} at {:?}: {err}", map.address);
            continue;
        }

        for pos in finder.find_iter(&haystack) {
            eprint!("{:08x}: ", map.address.start + pos);

            let bytes = &haystack[pos..];

            if let Ok(s) = CStr::from_bytes_until_nul(bytes) {
                eprintln!("{s:?}");
                continue;
            }

            let mut s = str::from_utf8(&bytes[..needle.len()]).unwrap();
            for len in needle.len() + 1.. {
                if let Ok(ok) = str::from_utf8(&bytes[..len]) {
                    s = ok;
                } else {
                    break;
                }
            }
            eprintln!("{s:?}..");
        }
    }

    Ok(())
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct Perms {
    read: bool,
    write: bool,
    execute: bool,
    shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
struct ParsePermsError;

impl FromStr for Perms {
    type Err = ParsePermsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 4] = s.as_bytes().try_into().map_err(|_| ParsePermsError)?;

        let read = match bytes[0] {
            b'r' => true,
            b'-' => false,
            _ => return Err(ParsePermsError),
        };

        let write = match bytes[1] {
            b'w' => true,
            b'-' => false,
            _ => return Err(ParsePermsError),
        };

        let execute = match bytes[2] {
            b'x' => true,
            b'-' => false,
            _ => return Err(ParsePermsError),
        };

        let shared = match bytes[3] {
            b's' => true,
            b'p' => false,
            _ => return Err(ParsePermsError),
        };

        Ok(Self {
            read,
            write,
            execute,
            shared,
        })
    }
}

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.read {
            f.write_char('r')?;
        } else {
            f.write_char('-')?;
        };

        if self.write {
            f.write_char('w')?;
        } else {
            f.write_char('-')?;
        };

        if self.execute {
            f.write_char('x')?;
        } else {
            f.write_char('-')?;
        };

        if self.shared {
            f.write_char('s')?;
        } else {
            f.write_char('p')?;
        };

        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
struct Map {
    address: Range<usize>,
    perms: Perms,
    offset: usize,
    dev: String,
    inode: ino_t,
    pathname: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
struct ParseMapError;

impl FromStr for Map {
    type Err = ParseMapError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split_ascii_whitespace();

        let address = {
            let address = iter.next().ok_or(ParseMapError)?;
            let (start, end) = address.split_once('-').ok_or(ParseMapError)?;
            let start = usize::from_str_radix(start, 16).map_err(|_| ParseMapError)?;
            let end = usize::from_str_radix(end, 16).map_err(|_| ParseMapError)?;
            start..end
        };

        let perms = {
            let perms = iter.next().ok_or(ParseMapError)?;
            perms.parse().map_err(|_| ParseMapError)?
        };

        let offset = {
            let offset = iter.next().ok_or(ParseMapError)?;
            usize::from_str_radix(offset, 16).map_err(|_| ParseMapError)?
        };

        let dev = iter.next().ok_or(ParseMapError)?;

        let inode = {
            let inode = iter.next().ok_or(ParseMapError)?;
            ino_t::from_str_radix(inode, 10).map_err(|_| ParseMapError)?
        };

        let pathname = iter.fold(String::new(), |mut acc, x| {
            if !acc.is_empty() {
                acc.push(' ');
            }
            acc.push_str(x);
            acc
        });

        Ok(Self {
            address,
            perms,
            offset,
            dev: dev.to_owned(),
            inode,
            pathname: pathname.to_owned(),
        })
    }
}

impl fmt::Display for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            address,
            perms,
            offset,
            dev,
            inode,
            pathname,
        } = self;
        let start = address.start;
        let end = address.end;

        write!(
            f,
            "{start:08x}-{end:08x} {perms} {offset:08x} {dev} {inode:<10} {pathname}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map() {
        let s = "08048000-08049000 r-xp 00000000 03:00 8312       /opt/test (deleted)";
        let map = Map {
            address: 0x08048000..0x08049000,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
                shared: false,
            },
            offset: 00000000,
            dev: "03:00".to_owned(),
            inode: 8312,
            pathname: "/opt/test (deleted)".to_owned(),
        };

        assert_eq!(map, s.parse().unwrap());
        assert_eq!(s, map.to_string());
    }
}
