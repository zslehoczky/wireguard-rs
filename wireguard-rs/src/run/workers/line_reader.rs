use std::io::{BufRead, BufReader, Read, Result};

pub enum ReadOutcome<T> {
    Ready(T),
    Eof,
}

pub fn read_line_block<R: Read>(reader: &mut BufReader<R>) -> Result<ReadOutcome<String>> {
    let mut result = String::new();

    loop {
        match read_line(reader, &mut result)? {
            ReadOutcome::Ready(line) => {
                if line.is_empty() {
                    break Ok(ReadOutcome::Ready(result));
                }
            }
            ReadOutcome::Eof => {
                break Ok(ReadOutcome::Eof);
            }
        }
    }
}

fn read_line<'buffer, R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &'buffer mut String,
) -> Result<ReadOutcome<&'buffer str>> {
    let prev_len = string_buffer.len();

    let n_chars = reader.read_line(string_buffer)?;

    if n_chars == 0 {
        return Ok(ReadOutcome::Eof);
    }

    match string_buffer[prev_len..].strip_suffix('\n') {
        Some(line) => Ok(ReadOutcome::Ready(line)),
        None => Ok(ReadOutcome::Eof),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_from_text(text: &'static str) -> (ReadOutcome<String>, Vec<String>) {
        let mut reader = BufReader::new(text.as_bytes());

        let read_outcome = read_line_block(&mut reader).unwrap();
        let lines = match &read_outcome {
            ReadOutcome::Ready(val) => val.lines().map(String::from).collect(),
            ReadOutcome::Eof => vec![],
        };

        (read_outcome, lines)
    }

    #[test]
    fn empty_input() {
        let (result, _) = read_from_text("");

        assert!(matches!(result, ReadOutcome::Eof));
    }

    #[test]
    fn incomplete_line() {
        let (result, _) = read_from_text("abc");

        assert!(matches!(result, ReadOutcome::Eof));
    }

    #[test]
    fn empty_line() {
        let (result, lines) = read_from_text("\n");

        assert!(matches!(result, ReadOutcome::Ready(_)));
        assert_eq!(lines, vec![""]);
    }

    #[test]
    fn non_empty_line() {
        let (result, _) = read_from_text("aaa\n");

        assert!(matches!(result, ReadOutcome::Eof));
    }

    #[test]
    fn single_line_block() {
        let (result, lines) = read_from_text("a\n\n");

        assert!(matches!(result, ReadOutcome::Ready(_)));
        assert_eq!(lines, vec!["a", ""]);
    }

    #[test]
    fn two_line_blocks() {
        const INPUT: &str = "a\n\nb\n\n";

        let mut reader = BufReader::new(INPUT.as_bytes());

        let read_outcome = read_line_block(&mut reader).unwrap();
        let lines = match &read_outcome {
            ReadOutcome::Ready(val) => val.lines().map(String::from).collect(),
            ReadOutcome::Eof => vec![],
        };

        assert!(matches!(read_outcome, ReadOutcome::Ready(_)));
        assert_eq!(lines, vec!["a", ""]);

        let read_outcome = read_line_block(&mut reader).unwrap();
        let lines = match &read_outcome {
            ReadOutcome::Ready(val) => val.lines().map(String::from).collect(),
            ReadOutcome::Eof => vec![],
        };

        assert!(matches!(read_outcome, ReadOutcome::Ready(_)));
        assert_eq!(lines, vec!["b", ""]);

        let read_outcome = read_line_block(&mut reader).unwrap();

        assert!(matches!(read_outcome, ReadOutcome::Eof));
    }
}
