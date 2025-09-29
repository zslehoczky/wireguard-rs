use std::process::{ExitCode, Termination};

pub enum MainResult {
    Good,
    NoDeviceNameSupplied,
    UAPIListenerCreationFailed(anyhow::Error),
    TUNDeviceCreationFailed(anyhow::Error),
    DropPriviligesFailed(anyhow::Error),
    DaemonizeFailed(anyhow::Error),
}

impl Termination for MainResult {
    fn report(self) -> ExitCode {
        match self {
            MainResult::Good => ExitCode::from(0),
            MainResult::NoDeviceNameSupplied => {
                eprintln!("No device name supplied");
                ExitCode::from(wrap_to_u8(-1))
            }
            MainResult::UAPIListenerCreationFailed(e) => {
                eprintln!("Failed to create UAPI listener: {}", e);
                ExitCode::from(wrap_to_u8(-2))
            }
            MainResult::TUNDeviceCreationFailed(e) => {
                eprintln!("Failed to create TUN device: {}", e);
                ExitCode::from(wrap_to_u8(-3))
            }
            MainResult::DropPriviligesFailed(e) => {
                eprintln!("Failed to drop privileges: {}", e);
                ExitCode::from(wrap_to_u8(-4))
            }
            MainResult::DaemonizeFailed(e) => {
                eprintln!("Failed to daemonize: {}", e);
                ExitCode::from(wrap_to_u8(-5))
            }
        }
    }
}

fn wrap_to_u8(value: i8) -> u8 {
    0u8.wrapping_add_signed(value)
}
