use std::process::ExitCode;

use wireguard_rs::run::{create_config_and_run, error::Error};

fn main() -> ExitCode {
    match create_config_and_run() {
        Ok(_) => ExitCode::SUCCESS,

        Err(error_reason) => {
            let error = Error::from(error_reason);

            eprintln!("{}", error.message);

            ExitCode::from(error.exit_code as u8)
        }
    }
}
