mod config_operation;
mod get;
mod set;

pub use config_operation::{ConfigOperation, parse_config_operation};

use super::{ConfigError, Configuration};

use get::serialize;
use set::LineParser;

pub fn handle_config_operation<C: Configuration>(
    config_operation: ConfigOperation,
    config: &mut C,
) -> Result<String, ConfigError> {
    match config_operation {
        ConfigOperation::Get => {
            log::debug!("UAPI, Get operation");

            Ok(serialize(config))
        }
        ConfigOperation::Set(key_value_pairs) => {
            log::debug!("UAPI, Set operation");

            let mut parser = LineParser::new(config);
            for (k, v) in key_value_pairs {
                parser.parse_line(&k, &v)?;
            }
            parser.finalize();

            Ok(String::new())
        }
    }
}
