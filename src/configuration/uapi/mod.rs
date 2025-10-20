mod get;
mod set;

use std::io::{BufRead, BufReader, Read, Write};

use super::{ConfigError, Configuration};

use get::serialize;
use set::LineParser;

const MAX_LINE_LENGTH: usize = 256;

pub fn handle<S: Read + Write, C: Configuration>(stream: &mut S, config: &mut C) {
    // process operation
    let res = parse_config_operation(stream).and_then(|operation| match operation {
        ConfigOperation::Get => {
            log::debug!("UAPI, Get operation");
            serialize(stream, config).map_err(|_| ConfigError::IOError)
        }
        ConfigOperation::Set(key_value_pairs) => {
            log::debug!("UAPI, Set operation");
            let mut parser = LineParser::new(config);
            for (k, v) in key_value_pairs {
                parser.parse_line(&k, &v)?;
            }
            Ok(parser.finalize())
        }
    });

    match res {
        Ok(_) => log::debug!("UAPI, Result of operation: OK"),
        Err(ref e) => log::error!("UAPI, Result of operation: {}", e),
    }

    // return errno
    let _ = stream.write("errno=".as_ref());
    let _ = stream.write(
        match res {
            Err(e) => e.errno().to_string(),
            Ok(()) => "0".to_owned(),
        }
        .as_ref(),
    );
    let _ = stream.write("\n\n".as_ref());
}

pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub fn parse_config_operation<S: Read + Write>(
    stream: &mut S,
) -> Result<ConfigOperation, ConfigError> {
    let mut buf_reader = BufReader::new(stream);

    match read_line(&mut buf_reader)?.as_str() {
        "get=1" => Ok(ConfigOperation::Get),
        "set=1" => {
            let mut key_value_pairs = Vec::new();
            while let ln = read_line(&mut buf_reader)?
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
