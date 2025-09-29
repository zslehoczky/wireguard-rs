use std::process::{ExitCode, Termination};

#[repr(i8)]
pub enum MainExitCode {
    Good = 0,
    NoDeviceNameSupplied = -1,
    UAPIListenerCreationFailed = -2,
    TUNDeviceCreationFailed = -3,
    DropPriviligesFailed = -4,
    DaemonizeFailed = -5,
    TUNDeviceError = -6,
    UAPIConnectionError = -7,
}

impl Into<ExitCode> for MainExitCode {
    fn into(self) -> ExitCode {
        ExitCode::from(self as u8)
    }
}

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
            MainResult::Good => MainExitCode::Good.into(),
            MainResult::NoDeviceNameSupplied => {
                eprintln!("No device name supplied");
                MainExitCode::NoDeviceNameSupplied.into()
            }
            MainResult::UAPIListenerCreationFailed(e) => {
                eprintln!("Failed to create UAPI listener: {}", e);
                MainExitCode::UAPIListenerCreationFailed.into()
            }
            MainResult::TUNDeviceCreationFailed(e) => {
                eprintln!("Failed to create TUN device: {}", e);
                MainExitCode::TUNDeviceCreationFailed.into()
            }
            MainResult::DropPriviligesFailed(e) => {
                eprintln!("Failed to drop privileges: {}", e);
                MainExitCode::DropPriviligesFailed.into()
            }
            MainResult::DaemonizeFailed(e) => {
                eprintln!("Failed to daemonize: {}", e);
                MainExitCode::DaemonizeFailed.into()
            }
        }
    }
}
