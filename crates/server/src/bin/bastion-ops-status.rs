//! Emits one aggregate, non-secret JSON snapshot for an operator or monitor.

use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: bastion-ops-status <database>");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let database = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    let snapshot = server::operational_snapshot(&database).unwrap_or_else(|error| {
        eprintln!("operational snapshot failed: {error}");
        std::process::exit(1);
    });
    let json = serde_json::to_string(&snapshot).unwrap_or_else(|error| {
        eprintln!("operational snapshot serialization failed: {error}");
        std::process::exit(1);
    });
    println!("{json}");
}
