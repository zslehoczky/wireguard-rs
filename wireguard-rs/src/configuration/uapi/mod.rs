mod get;
mod set;

use std::io::{BufRead, BufReader, Read, Write};

use super::{ConfigError, Configuration};

use get::serialize;
use set::LineParser;

const MAX_LINE_LENGTH: usize = 256;

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

pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub fn parse_config_operation<S: Read + Write>(
    buf_reader: &mut BufReader<&mut S>,
) -> Result<ConfigOperation, ConfigError> {
    match read_line(buf_reader)?.as_str() {
        "get=1" => Ok(ConfigOperation::Get),
        "set=1" => {
            let mut key_value_pairs = Vec::new();
            while let ln = read_line(buf_reader)?
                && ln != ""
            {
                key_value_pairs.push(parse_key_value_pair(ln.as_str())?);
            }
            Ok(ConfigOperation::Set { 0: key_value_pairs })
        }
        _ => Err(ConfigError::InvalidOperation),
    }
}

fn read_line<R: Read>(buf_reader: &mut BufReader<R>) -> Result<String, ConfigError> {
    let mut line = String::new();

    let n_chars = buf_reader
        .read_line(&mut line)
        .map_err(|_| ConfigError::IOError)?;

    if n_chars > MAX_LINE_LENGTH {
        return Err(ConfigError::LineTooLong);
    }

    Ok(line)
}

fn parse_key_value_pair(ln: &str) -> Result<(String, String), ConfigError> {
    let mut split = ln.splitn(2, '=');
    match (split.next(), split.next()) {
        (Some(key), Some(value)) => Ok((key.to_string(), value.to_string())),
        _ => Err(ConfigError::LineTooLong),
    }
}
