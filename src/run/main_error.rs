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

pub enum MainError {
    None,
    NoDeviceNameSupplied,
    UAPIListenerCreationFailed(anyhow::Error),
    TUNDeviceCreationFailed(anyhow::Error),
    DropPriviligesFailed(anyhow::Error),
    DaemonizeFailed(anyhow::Error),
}

impl Termination for MainError {
    fn report(self) -> ExitCode {
        match self {
            MainError::None => MainExitCode::Good.into(),
            MainError::NoDeviceNameSupplied => {
                eprintln!("No device name supplied");
                MainExitCode::NoDeviceNameSupplied.into()
            }
            MainError::UAPIListenerCreationFailed(e) => {
                eprintln!("Failed to create UAPI listener: {}", e);
                MainExitCode::UAPIListenerCreationFailed.into()
            }
            MainError::TUNDeviceCreationFailed(e) => {
                eprintln!("Failed to create TUN device: {}", e);
                MainExitCode::TUNDeviceCreationFailed.into()
            }
            MainError::DropPriviligesFailed(e) => {
                eprintln!("Failed to drop privileges: {}", e);
                MainExitCode::DropPriviligesFailed.into()
            }
            MainError::DaemonizeFailed(e) => {
                eprintln!("Failed to daemonize: {}", e);
                MainExitCode::DaemonizeFailed.into()
            }
        }
    }
}
