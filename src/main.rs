use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;
use std::{fs, io};

use clap::Parser;
use libc::pid_t;
use mem_find::Finder;
use nix::unistd::{Uid, User};

macro_rules! unwrap_or_continue {
    ($result:expr) => {
        match $result {
            Ok(ok) => ok,
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        }
    };
}

/// Searches the memory of a process (haystack) for a string (needle).
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The string to search for.
    needle: String,

    /// The PID of the process to search.
    #[clap(id = "PID")]
    pids: Vec<pid_t>,
}

fn main() -> ExitCode {
    env_logger::init();

    let args = Args::parse();

    args.run()
}

impl Args {
    fn run(&self) -> ExitCode {
        let finder = Finder::new(&self.needle);

        let mut found = false;
        for pid in self.pids.iter().copied() {
            unwrap_or_continue!(self.print_info(pid));

            for res in unwrap_or_continue!(finder.find_iter(pid)) {
                let (pos, s) = unwrap_or_continue!(res);

                println!("{pos:08x}: {s:?}");
                found = true;
            }
        }

        if found {
            ExitCode::SUCCESS
        } else {
            eprintln!("Not found");
            ExitCode::FAILURE
        }
    }

    fn print_info(&self, pid: pid_t) -> io::Result<()> {
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

        let needle = &self.needle;
        eprintln!("Searching for {needle:?} in process {pid} by {name}: `{cmdline}`");

        Ok(())
    }
}
