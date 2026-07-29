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
        Some("local-init") if args.len() == 4 => {
            match telosieve::engine::initialize_actuator_file(
                Path::new(&args[2]),
                Path::new(&args[3]),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-show") if args.len() == 3 => {
            match telosieve::engine::read_actuator_snapshot_file(Path::new(&args[2])) {
                Ok(snapshot) => {
                    println!(
                        "{}",
                        serde_json::to_string(&snapshot).expect("actuator snapshot serializes")
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error),
            }
        }
        Some("local-backup") if args.len() == 4 => {
            match telosieve::engine::backup_actuator_file(Path::new(&args[2]), Path::new(&args[3]))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-restore") if args.len() == 4 => {
            match telosieve::engine::restore_actuator_file(Path::new(&args[2]), Path::new(&args[3]))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-recover") if args.len() == 3 => {
            match telosieve::engine::recover_actuator_file(Path::new(&args[2])) {
                Ok(outcome) => {
                    println!(
                        "{}",
                        serde_json::to_string(&outcome).expect("recovery outcome serializes")
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error),
            }
        }
        Some("local-upgrade") if args.len() == 3 => {
            match telosieve::engine::upgrade_actuator_file(Path::new(&args[2])) {
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
        Some("apply-local") if args.len() == 6 => {
            emit(telosieve::engine::run_scenario_file_actuated(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                Path::new(&args[5]),
            ))
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  telosieve anchor-init <scenario.json> <anchor.json>\n  \
         telosieve local-init <scenario.json> <actuator.json>\n  \
         telosieve local-show <actuator.json>\n  \
         telosieve local-backup <actuator.json> <backup.json>\n  \
         telosieve local-restore <actuator.json> <backup.json>\n  \
         telosieve local-recover <actuator.json>\n  \
         telosieve local-upgrade <actuator.json>\n  \
         telosieve run <scenario.json> <certificate.json> <ledger.jsonl>\n  \
         telosieve run-anchored <scenario.json> <certificate.json> \
         <ledger.jsonl> <anchor.json>\n  \
         telosieve apply-local <scenario.json> <certificate.json> \
         <ledger.jsonl> <actuator.json>"
    );
    ExitCode::from(2)
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
