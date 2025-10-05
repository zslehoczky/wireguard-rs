use crate::run::error::ErrorReason;

use std::env;

pub struct Config {
    pub name: String,
    pub drop_privileges: bool,
    pub foreground: bool,
}

impl Config {
    pub fn from_args(mut args: env::Args) -> Result<Config, ErrorReason> {
        let mut name = None;
        let mut drop_privileges = true;
        let mut foreground = false;

        // skip path (argv[0])
        args.next();
        for arg in args {
            match arg.as_str() {
                "--foreground" | "-f" => {
                    foreground = true;
                }
                "--disable-drop-privileges" => {
                    drop_privileges = false;
                }
                dev => name = Some(dev.to_owned()),
            }
        }

        let name = name.ok_or(ErrorReason::NoDeviceNameSupplied)?;

        Ok(Config {
            name,
            drop_privileges,
            foreground,
        })
    }
}
