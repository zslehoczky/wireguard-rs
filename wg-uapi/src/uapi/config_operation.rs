use std::io::{BufRead, BufReader, Read};

use super::ConfigError;

pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub enum ReadNonEmptyLinesResult<'buffer> {
    StreamOpen(Result<Vec<&'buffer str>, ConfigError>),
    StreamClosed,
}

pub fn read_non_empty_lines<'buffer, R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &'buffer mut String,
) -> ReadNonEmptyLinesResult<'buffer> {
    string_buffer.clear();

    match read_lines(reader, string_buffer) {
        ReadLinesResult::Eof => {
            return ReadNonEmptyLinesResult::StreamClosed;
        }
        ReadLinesResult::Err => {
            return ReadNonEmptyLinesResult::StreamOpen(Err(ConfigError::IOError));
        }
        _ => (),
    };

    ReadNonEmptyLinesResult::StreamOpen(Ok(string_buffer
        .lines()
        .filter(|&line| !line.is_empty())
        .collect()))
}

pub fn parse_config_operation(lines: Vec<&str>) -> Result<ConfigOperation, ConfigError> {
    if lines.is_empty() {
        log::error!("Empty line instead of operation");

        return Err(ConfigError::InvalidOperation);
    }

    let arguments_provided = lines.len() > 1;

    match *lines.first().expect("empty vector already handled") {
        "get=1" => {
            if arguments_provided {
                log::warn!("Get operation should be followed by an empty line");
            }

            Ok(ConfigOperation::Get)
        }
        "set=1" => {
            if !arguments_provided {
                log::warn!("Set operation should be followed by arguments");
            }

            let mut key_value_pairs = Vec::new();

            for &line in &lines[1..] {
                key_value_pairs.push(parse_key_value_pair(line)?);
            }

            Ok(ConfigOperation::Set(key_value_pairs))
        }
        op => {
            log::error!("Unknown operation: {op}");

            Err(ConfigError::InvalidOperation)
        }
    }
}

enum ReadLineResult<'buffer> {
    Ok(&'buffer str),
    Eof,
    Err,
}

fn read_line<'buffer, R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &'buffer mut String,
) -> ReadLineResult<'buffer> {
    let prev_len = string_buffer.len();

    let n_chars = match reader.read_line(string_buffer) {
        Ok(n_chars) => n_chars,
        Err(_) => {
            return ReadLineResult::Err;
        }
    };

    if n_chars == 0 {
        return ReadLineResult::Eof;
    }

    let line_content_without_newline = &string_buffer[prev_len..(string_buffer.len() - 1)];

    ReadLineResult::Ok(line_content_without_newline)
}

enum ReadLinesResult {
    Ok,
    Eof,
    Err,
}

fn read_lines<R: Read>(reader: &mut BufReader<R>, string_buffer: &mut String) -> ReadLinesResult {
    loop {
        match read_line(reader, string_buffer) {
            ReadLineResult::Ok(line) => {
                if line.is_empty() {
                    return ReadLinesResult::Ok;
                }
            }
            ReadLineResult::Eof => {
                return ReadLinesResult::Eof;
            }
            ReadLineResult::Err => {
                return ReadLinesResult::Err;
            }
        }
    }
}

fn parse_key_value_pair(ln: &str) -> Result<(String, String), ConfigError> {
    match ln.split_once('=') {
        Some((key, value)) => Ok((key.to_string(), value.to_string())),
        _ => {
            log::error!("Unable to parse key-value pair from string: {ln}");

            Err(ConfigError::InvalidKeyValuePair)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<'buffer> ReadNonEmptyLinesResult<'buffer> {
        fn map<U, F: FnOnce(Result<Vec<&'buffer str>, ConfigError>) -> U>(self, f: F) -> Option<U> {
            match self {
                ReadNonEmptyLinesResult::StreamOpen(result) => Some(f(result)),
                ReadNonEmptyLinesResult::StreamClosed => None,
            }
        }
    }

    fn parse_from_text(text: &'static str) -> Option<Result<ConfigOperation, ConfigError>> {
        let mut reader = BufReader::new(text.as_bytes());
        let mut string_buffer = String::new();

        read_non_empty_lines(&mut reader, &mut string_buffer)
            .map(|lines_result| lines_result.and_then(parse_config_operation))
    }

    fn unwrap_config_operation(
        config_operation: Option<Result<ConfigOperation, ConfigError>>,
    ) -> ConfigOperation {
        assert!(config_operation.is_some());

        let config_operation = config_operation.unwrap();
        assert!(config_operation.is_ok());

        config_operation.unwrap()
    }

    #[test]
    fn eof() {
        let config_operation = parse_from_text("");

        assert!(config_operation.is_none());
    }

    #[test]
    fn empty_line() {
        let config_operation = parse_from_text("\n");

        assert!(config_operation.is_some());
        assert!(matches!(
            config_operation.unwrap(),
            Err(ConfigError::InvalidOperation)
        ));
    }

    #[test]
    fn get() {
        const INPUT: &str = "get=1\n\
                            \n";

        assert!(matches!(
            unwrap_config_operation(parse_from_text(INPUT)),
            ConfigOperation::Get
        ));
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

                assert_eq!(key_value_pairs[0], (String::from("a"), String::from("1")));
                assert_eq!(key_value_pairs[1], (String::from("b"), String::from("2")));
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

        assert!(config_operation.is_some());
        assert!(matches!(
            config_operation.unwrap(),
            Err(ConfigError::InvalidOperation)
        ));
    }

    #[test]
    fn invalid_key_value() {
        const INPUT: &str = "set=1\n\
                            a\n\
                            \n";

        let config_operation = parse_from_text(INPUT);

        assert!(config_operation.is_some());
        assert!(matches!(
            config_operation.unwrap(),
            Err(ConfigError::InvalidKeyValuePair)
        ));
    }

    #[test]
    fn parse_two_messages() {
        const INPUT: &str = "get=1\n\
                            \n\
                            get=1\n\
                            \n";

        let mut reader = BufReader::new(INPUT.as_bytes());
        let mut string_buffer = String::new();

        let _ = unwrap_config_operation(
            read_non_empty_lines(&mut reader, &mut string_buffer)
                .map(|lines_result| lines_result.and_then(parse_config_operation)),
        );
        let _ = unwrap_config_operation(
            read_non_empty_lines(&mut reader, &mut string_buffer)
                .map(|lines_result| lines_result.and_then(parse_config_operation)),
        );
    }
}
