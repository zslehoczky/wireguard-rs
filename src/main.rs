use wireguard_rs::run::{main_error::MainError, run::create_config_and_run};

fn main() -> MainError {
    match create_config_and_run() {
        Ok(()) => MainError::None,
        Err(err) => err,
    }
}
