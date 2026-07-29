use std::{env, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 || args[1] != "run" {
        eprintln!("usage: telosieve run <scenario.json> <certificate.json> <ledger.jsonl>");
        return ExitCode::from(2);
    }
    match telosieve::engine::run_scenario_file(
        Path::new(&args[2]),
        Path::new(&args[3]),
        Path::new(&args[4]),
    ) {
        Ok(certificate) => {
            println!(
                "{}",
                serde_json::to_string(&certificate).expect("certificate serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("telosieve: {error}");
            ExitCode::FAILURE
        }
    }
}
