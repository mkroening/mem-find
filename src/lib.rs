use std::ffi::CStr;
use std::fmt::{self, Write};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::str::{self, FromStr};

use corosensei::{Coroutine, CoroutineResult};
use libc::{ino_t, pid_t};
use log::{error, info};
use memchr::memmem;

pub struct Finder<'n> {
    finder: memmem::Finder<'n>,
}

impl<'n> Finder<'n> {
    #[inline]
    pub fn new<B: ?Sized + AsRef<[u8]>>(needle: &'n B) -> Finder<'n> {
        let finder = memmem::Finder::new(needle);
        Self { finder }
    }

    #[inline]
    pub fn find_iter(&self, pid: pid_t) -> io::Result<FindIter> {
        FindIter::new(self.finder.as_ref(), pid)
    }
}

#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct FindIter {
    coroutine: Coroutine<(), io::Result<(usize, String)>, ()>,
}

impl FindIter {
    fn new(finder: memmem::Finder<'_>, pid: pid_t) -> io::Result<Self> {
        let maps = File::open(format!("/proc/{pid}/maps"))?;
        let maps = BufReader::new(maps);

        let mem_path = format!("/proc/{pid}/mem");
        let mem = File::open(&mem_path)?;

        // FIXME: It would be great to make the coroutine depend on `'n` once it is possible.
        let finder = finder.into_owned();
        let coroutine = Coroutine::new(move |yielder, _input| {
            for map in maps.lines() {
                let map = match map {
                    Ok(map) => map,
                    Err(err) => {
                        yielder.suspend(Err(err));
                        continue;
                    }
                };
                let map = match map.parse::<Map>() {
                    Ok(map) => map,
                    Err(err) => {
                        error!("could not parse map: {map} ({err:?})");
                        yielder.suspend(Err(io::Error::from(io::ErrorKind::InvalidData)));
                        continue;
                    }
                };

                info!("{map}");

                if !map.perms.read {
                    continue;
                }

                if map.pathname.starts_with("[vvar") {
                    continue;
                }

                let mut haystack = vec![0; map.address.end - map.address.start];

                if let Err(err) = mem.read_exact_at(&mut haystack, map.address.start as u64) {
                    error!("could not read {mem_path} at {:?}: {err}", map.address);
                    yielder.suspend(Err(err));
                    continue;
                }

                for spos in finder.find_iter(&haystack) {
                    let pos = map.address.start + spos;

                    let bytes = &haystack[spos..];

                    if let Ok(s) = CStr::from_bytes_until_nul(bytes) {
                        let s = s.to_string_lossy().into_owned();
                        yielder.suspend(Ok((pos, s)));
                        continue;
                    }

                    let mut s = "";
                    for len in 1.. {
                        if let Ok(ok) = str::from_utf8(&bytes[..len]) {
                            s = ok;
                        } else {
                            break;
                        }
                    }

                    let s = s.to_owned();
                    yielder.suspend(Ok((pos, s)));
                }
            }
        });

        Ok(Self { coroutine })
    }
}

impl Iterator for FindIter {
    type Item = io::Result<(usize, String)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.coroutine.done() {
            return None;
        }

        match self.coroutine.resume(()) {
            CoroutineResult::Yield(val) => Some(val),
            CoroutineResult::Return(()) => None,
        }
    }
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
            pathname: pathname.clone(),
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
