mod get;
mod set;

use std::io::{BufRead, BufReader, Read, Write};

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

pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub fn parse_config_operation<S: Read + Write>(
    reader: &mut BufReader<&mut S>,
    string_buffer: &mut String,
) -> Result<Option<ConfigOperation>, ConfigError> {
    string_buffer.clear();

    match read_line(reader, string_buffer)? {
        Some(line) => {
            log::trace!("Config operation parsed: {line}");

            match line {
                "get=1" => {
                    // parse trailing empty line
                    match read_line(reader, string_buffer)? {
                        Some("") => Ok(Some(ConfigOperation::Get)),
                        None => Ok(None), // EOF reached
                        _ => {
                            log::error!("Missing empty line after operation");

                            Err(ConfigError::NoTrailingEmptyLine)
                        }
                    }
                }
                "set=1" => {
                    let mut key_value_pairs = Vec::new();

                    'read_argument_lines: loop {
                        if let Some(line) = read_line(reader, string_buffer)? {
                            if line == "" {
                                break 'read_argument_lines Ok(Some(ConfigOperation::Set {
                                    0: key_value_pairs,
                                }));
                            }

                            key_value_pairs.push(parse_key_value_pair(line)?);
                        } else {
                            break 'read_argument_lines Ok(None); // EOF reached
                        }
                    }
                }
                op => {
                    log::error!("Unknown operation: {op}");

                    Err(ConfigError::InvalidOperation)
                }
            }
        }
        None => Ok(None), // EOF reached
    }
}

fn read_line<'buffer, R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &'buffer mut String,
) -> Result<Option<&'buffer str>, ConfigError> {
    let prev_len = string_buffer.len();

    let n_chars = reader
        .read_line(string_buffer)
        .map_err(|_| ConfigError::IOError)?;

    if n_chars == 0 {
        // EOF reached
        return Ok(None);
    }

    let line_content_without_newline = &string_buffer[prev_len..(string_buffer.len() - 1)];

    Ok(Some(line_content_without_newline))
}

fn parse_key_value_pair(ln: &str) -> Result<(String, String), ConfigError> {
    let mut split = ln.splitn(2, '=');
    match (split.next(), split.next()) {
        (Some(key), Some(value)) => Ok((key.to_string(), value.to_string())),
        _ => {
            log::error!("Unable to parse key-value pair from string: {ln}");

            Err(ConfigError::InvalidKeyValuePair)
        }
    }
}
