use std::io::{BufRead, BufReader, Read, Write};

use super::ConfigError;

pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub fn parse_config_operation<S: Read + Write>(
    reader: &mut BufReader<&mut S>,
    string_buffer: &mut String,
) -> Result<Option<ConfigOperation>, ConfigError> {
    string_buffer.clear();

    let read_lines_ok = 'read_lines: loop {
        if let Some(line) = read_line(reader, string_buffer)? {
            if line == "" {
                break 'read_lines true;
            }
        } else {
            break 'read_lines false; // EOF reached
        }
    };

    if !read_lines_ok {
        return Ok(None); // EOF reached
    }

    let lines: Vec<&str> = string_buffer.lines().filter(|&line| line != "").collect();

    if lines.len() == 0 {
        log::error!("Empty line instead of operation");

        return Err(ConfigError::InvalidOperation);
    }

    let arguments_provided = lines.len() > 1;

    match *lines.get(0).expect("empty vector already handled") {
        "get=1" => {
            if arguments_provided {
                log::warn!("Get operation should be followed by an empty line");
            }

            Ok(Some(ConfigOperation::Get))
        }
        "set=1" => {
            if !arguments_provided {
                log::warn!("Set operation should be followed by arguments");
            }

            let mut key_value_pairs = Vec::new();

            for &line in &lines[1..] {
                key_value_pairs.push(parse_key_value_pair(line)?);
            }

            Ok(Some(ConfigOperation::Set(key_value_pairs)))
        }
        op => {
            log::error!("Unknown operation: {op}");

            Err(ConfigError::InvalidOperation)
        }
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
