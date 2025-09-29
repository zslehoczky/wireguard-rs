use crate::run::main_result::MainResult;

use std::env;

pub struct Config {
    pub name: String,
    pub drop_privileges: bool,
    pub foreground: bool,
}

impl Config {
    pub fn from_args(mut args: env::Args) -> Result<Config, MainResult> {
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

        let name = name.ok_or(MainResult::NoDeviceNameSupplied)?;

        Ok(Config {
            name,
            drop_privileges,
            foreground,
        })
    }
}
