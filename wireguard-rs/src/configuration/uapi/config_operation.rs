use std::io::{BufRead, BufReader, Read};

use super::ConfigError;

pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub fn parse_config_operation<R: Read>(
    reader: &mut BufReader<R>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_from_text(text: &'static str) -> Result<Option<ConfigOperation>, ConfigError> {
        let mut reader = BufReader::new(text.as_bytes());
        let mut string_buffer = String::new();

        parse_config_operation(&mut reader, &mut string_buffer)
    }

    fn unwrap_config_operation(
        config_operation: Result<Option<ConfigOperation>, ConfigError>,
    ) -> ConfigOperation {
        assert!(config_operation.is_ok());

        let config_operation = config_operation.unwrap();
        assert!(config_operation.is_some());

        config_operation.unwrap()
    }

    #[test]
    fn eof() {
        let config_operation = parse_from_text("");

        assert!(config_operation.is_ok());
        assert!(config_operation.unwrap().is_none());
    }

    #[test]
    fn empty_line() {
        let config_operation = parse_from_text("\n");

        assert!(config_operation.is_err());

        match config_operation.err().unwrap() {
            ConfigError::InvalidOperation => (),
            _ => {
                panic!();
            }
        }
    }

    #[test]
    fn get() {
        const INPUT: &str = "get=1\n\
                            \n";

        match unwrap_config_operation(parse_from_text(INPUT)) {
            ConfigOperation::Get => (),
            _ => {
                panic!();
            }
        }
    }

    #[test]
    fn set() {
        const INPUT: &str = "set=1\n\
                            a=1\n\
                            b=2\n\
                            \n";

        match unwrap_config_operation(parse_from_text(INPUT)) {
            ConfigOperation::Set(key_value_pairs) => {
                assert_eq!(key_value_pairs.len(), 2);

                let (key, value) = &key_value_pairs[0];
                assert_eq!(key, "a");
                assert_eq!(value, "1");

                let (key, value) = &key_value_pairs[1];
                assert_eq!(key, "b");
                assert_eq!(value, "2");
            }
            _ => {
                panic!();
            }
        }
    }

    #[test]
    fn invalid_operation() {
        const INPUT: &str = "operation\n\
                            \n";

        let config_operation = parse_from_text(INPUT);

        assert!(config_operation.is_err());

        match config_operation.err().unwrap() {
            ConfigError::InvalidOperation => (),
            _ => {
                panic!();
            }
        }
    }

    #[test]
    fn invalid_key_value() {
        const INPUT: &str = "set=1\n\
                            a\n\
                            \n";

        let config_operation = parse_from_text(INPUT);

        assert!(config_operation.is_err());

        match config_operation.err().unwrap() {
            ConfigError::InvalidKeyValuePair => (),
            _ => {
                panic!();
            }
        }
    }

    #[test]
    fn parse_two_messages() {
        const INPUT: &str = "get=1\n\
                            \n\
                            get=1\n\
                            \n";

        let mut reader = BufReader::new(INPUT.as_bytes());
        let mut string_buffer = String::new();

        let _ = unwrap_config_operation(parse_config_operation(&mut reader, &mut string_buffer));
        let _ = unwrap_config_operation(parse_config_operation(&mut reader, &mut string_buffer));
    }
}
