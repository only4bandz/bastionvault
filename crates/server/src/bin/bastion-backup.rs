//! Creates a coherent, verified SQLite backup without overwriting a prior one.

use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: bastion-backup <source-database> <new-backup-path>");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let source = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let destination = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    if let Err(error) = server::backup_database(&source, &destination) {
        eprintln!("backup failed: {error}");
        std::process::exit(1);
    }
    println!("verified backup created at {}", destination.display());
}
