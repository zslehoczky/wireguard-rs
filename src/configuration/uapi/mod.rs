mod get;
mod set;

use std::io::{Read, Write};

use super::{ConfigError, Configuration};

use get::serialize;
use set::LineParser;

const MAX_LINE_LENGTH: usize = 256;

pub fn handle<S: Read + Write, C: Configuration>(stream: &mut S, config: &mut C) {
    // process operation
    let res = get_operation(stream).and_then(|operation| match operation {
        Operation::Get => {
            log::debug!("UAPI, Get operation");
            serialize(stream, config).map_err(|_| ConfigError::IOError)
        }
        Operation::Set => {
            log::debug!("UAPI, Set operation");
            let mut parser = LineParser::new(config);
            loop {
                let ln = readline(stream)?;
                if ln == "" {
                    break;
                }
                let (k, v) = keypair(ln.as_str())?;
                parser.parse_line(k, v)?;
            }
            parser.parse_line("", "")
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

enum Operation {
    Get,
    Set,
}

// read operation line
fn get_operation<S: Read + Write>(stream: &mut S) -> Result<Operation, ConfigError> {
    match readline(stream)?.as_str() {
        "get=1" => Ok(Operation::Get),
        "set=1" => Ok(Operation::Set),
        _ => Err(ConfigError::InvalidOperation),
    }
}

// read string up to maximum length (why is this not in std?)
fn readline<R: Read>(reader: &mut R) -> Result<String, ConfigError> {
    let mut m: [u8; 1] = [0u8];
    let mut l: String = String::with_capacity(MAX_LINE_LENGTH);
    while reader.read_exact(&mut m).is_ok() {
        let c = m[0] as char;
        if c == '\n' {
            log::trace!("UAPI, line: {}", l);
            return Ok(l);
        };
        l.push(c);
        if l.len() > MAX_LINE_LENGTH {
            return Err(ConfigError::LineTooLong);
        }
    }
    Err(ConfigError::IOError)
}

// split into (key, value) pair
fn keypair(ln: &str) -> Result<(&str, &str), ConfigError> {
    let mut split = ln.splitn(2, '=');
    match (split.next(), split.next()) {
        (Some(key), Some(value)) => Ok((key, value)),
        _ => Err(ConfigError::LineTooLong),
    }
}
