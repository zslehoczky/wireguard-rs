use std::iter::Iterator;

use super::ConfigError;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigOperation {
    Get,
    Set(Vec<(String, String)>),
}

pub fn parse_config_operation<'a, I: Iterator<Item = &'a str>>(
    mut lines: I,
) -> Result<ConfigOperation, ConfigError> {
    let first_line = match lines.next() {
        Some(line) => line,
        None => {
            log::error!("Empty line instead of operation");

            return Err(ConfigError::InvalidOperation);
        }
    };

    match first_line {
        "get=1" => Ok(ConfigOperation::Get),
        "set=1" => {
            let key_value_pairs = lines
                .map(parse_key_value_pair)
                .collect::<Result<Vec<_>, ConfigError>>()?;

            Ok(ConfigOperation::Set(key_value_pairs))
        }
        op => {
            log::error!("Unknown operation: {op}");

            Err(ConfigError::InvalidOperation)
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

    fn parse_from_text(text: &'static str) -> Result<ConfigOperation, ConfigError> {
        let string_buffer = text.to_string();

        parse_config_operation(string_buffer.lines().take_while(|&line| !line.is_empty()))
    }

    fn unwrap_config_operation(
        config_operation: Result<ConfigOperation, ConfigError>,
    ) -> ConfigOperation {
        assert!(config_operation.is_ok());

        config_operation.unwrap()
    }

    #[test]
    fn empty_line() {
        let config_operation = parse_from_text("\n");

        assert!(matches!(
            config_operation,
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

        assert_eq!(
            unwrap_config_operation(parse_from_text(INPUT)),
            ConfigOperation::Set(vec![
                (String::from("a"), String::from("1")),
                (String::from("b"), String::from("2"))
            ])
        );
    }

    #[test]
    fn invalid_operation() {
        const INPUT: &str = "operation\n\
                            \n";

        let config_operation = parse_from_text(INPUT);

        assert!(matches!(
            config_operation,
            Err(ConfigError::InvalidOperation)
        ));
    }

    #[test]
    fn invalid_key_value() {
        const INPUT: &str = "set=1\n\
                            a\n\
                            \n";

        let config_operation = parse_from_text(INPUT);

        assert!(matches!(
            config_operation,
            Err(ConfigError::InvalidKeyValuePair)
        ));
    }
}
