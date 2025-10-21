#[repr(i8)]
pub enum ExitCode {
    NoDeviceNameSupplied = -1,
    UAPIListenerCreationFailed = -2,
    TUNDeviceCreationFailed = -3,
    DropPriviligesFailed = -4,
    DaemonizeFailed = -5,
    TUNDeviceError = -6,
    UAPIConnectionError = -7,
}

pub enum ErrorReason {
    NoDeviceNameSupplied,
    UAPIListenerCreationFailed(anyhow::Error),
    TUNDeviceCreationFailed(anyhow::Error),
    DropPriviligesFailed(anyhow::Error),
    DaemonizeFailed(anyhow::Error),
}

pub struct Error {
    pub message: String,
    pub exit_code: ExitCode,
}

impl From<ErrorReason> for Error {
    fn from(error_reason: ErrorReason) -> Error {
        match error_reason {
            ErrorReason::NoDeviceNameSupplied => Error {
                message: "No device name supplied".to_string(),
                exit_code: ExitCode::NoDeviceNameSupplied,
            },
            ErrorReason::UAPIListenerCreationFailed(e) => Error {
                message: format!("Failed to create UAPI listener: {}", e),
                exit_code: ExitCode::UAPIListenerCreationFailed,
            },
            ErrorReason::TUNDeviceCreationFailed(e) => Error {
                message: format!("Failed to create TUN device: {}", e),
                exit_code: ExitCode::TUNDeviceCreationFailed,
            },
            ErrorReason::DropPriviligesFailed(e) => Error {
                message: format!("Failed to drop privileges: {}", e),
                exit_code: ExitCode::DropPriviligesFailed,
            },
            ErrorReason::DaemonizeFailed(e) => Error {
                message: format!("Failed to daemonize: {}", e),
                exit_code: ExitCode::DaemonizeFailed,
            },
        }
    }
}
