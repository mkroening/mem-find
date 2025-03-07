use std::process::ExitCode;

use clap::Parser;
use libc::pid_t;

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
            if let Err(err) = mem_find::find(self.verbose, &self.needle, pid) {
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
