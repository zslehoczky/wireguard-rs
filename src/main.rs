use wireguard_rs::run::{MainResult, create_config_and_run};

fn main() -> MainResult {
    if let Err(result) = create_config_and_run() {
        return result;
    }

    MainResult::Good
}
