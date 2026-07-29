use std::{env, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("anchor-init") if args.len() == 4 => {
            match telosieve::engine::initialize_anchor_file(
                Path::new(&args[2]),
                Path::new(&args[3]),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("run") if args.len() == 5 => emit(telosieve::engine::run_scenario_file(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        )),
        Some("run-anchored") if args.len() == 6 => {
            emit(telosieve::engine::run_scenario_file_anchored(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                Path::new(&args[5]),
            ))
        }
        _ => {
            eprintln!(
                "usage:\n  telosieve anchor-init <scenario.json> <anchor.json>\n  \
                 telosieve run <scenario.json> <certificate.json> <ledger.jsonl>\n  \
                 telosieve run-anchored <scenario.json> <certificate.json> \
                 <ledger.jsonl> <anchor.json>"
            );
            ExitCode::from(2)
        }
    }
}

fn emit(
    result: Result<telosieve::certificate::Certificate, telosieve::engine::RunError>,
) -> ExitCode {
    match result {
        Ok(certificate) => {
            println!(
                "{}",
                serde_json::to_string(&certificate).expect("certificate serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

fn fail(error: &telosieve::engine::RunError) -> ExitCode {
    eprintln!("telosieve: {error}");
    ExitCode::FAILURE
}
