use std::io::{BufRead, BufReader, Error, Read};

pub enum ReadLinesResult {
    Ok,
    Eof,
    Err(Error),
}

pub fn read_line_block<R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &mut String,
) -> ReadLinesResult {
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
            ReadLineResult::Err(err) => {
                return ReadLinesResult::Err(err);
            }
        }
    }
}

enum ReadLineResult<'buffer> {
    Ok(&'buffer str),
    Eof,
    Err(Error),
}

fn read_line<'buffer, R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &'buffer mut String,
) -> ReadLineResult<'buffer> {
    let prev_len = string_buffer.len();

    let n_chars = match reader.read_line(string_buffer) {
        Ok(n_chars) => n_chars,
        Err(err) => {
            return ReadLineResult::Err(err);
        }
    };

    if n_chars == 0 {
        return ReadLineResult::Eof;
    }

    let line_content_without_newline = match string_buffer[prev_len..].strip_suffix('\n') {
        Some(line) => line,
        None => {
            return ReadLineResult::Eof;
        }
    };

    ReadLineResult::Ok(line_content_without_newline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_from_text(text: &'static str) -> (ReadLinesResult, Vec<String>) {
        let mut reader = BufReader::new(text.as_bytes());
        let mut string_buffer = String::new();

        (
            read_line_block(&mut reader, &mut string_buffer),
            string_buffer.lines().map(String::from).collect(),
        )
    }

    #[test]
    fn empty_input() {
        let (result, _) = read_from_text("");

        assert!(matches!(result, ReadLinesResult::Eof));
    }

    #[test]
    fn incomplete_line() {
        let (result, _) = read_from_text("abc");

        assert!(matches!(result, ReadLinesResult::Eof));
    }

    #[test]
    fn empty_line() {
        let (result, lines) = read_from_text("\n");

        assert!(matches!(result, ReadLinesResult::Ok));
        assert_eq!(lines, vec![""]);
    }

    #[test]
    fn non_empty_line() {
        let (result, _) = read_from_text("aaa\n");

        assert!(matches!(result, ReadLinesResult::Eof));
    }

    #[test]
    fn single_line_block() {
        let (result, lines) = read_from_text("a\n\n");

        assert!(matches!(result, ReadLinesResult::Ok));
        assert_eq!(lines, vec!["a", ""]);
    }

    #[test]
    fn two_line_blocks() {
        const INPUT: &str = "a\n\nb\n\n";

        let mut reader = BufReader::new(INPUT.as_bytes());
        let mut string_buffer = String::new();

        assert!(matches!(
            read_line_block(&mut reader, &mut string_buffer),
            ReadLinesResult::Ok
        ));
        let lines: Vec<_> = string_buffer.lines().collect();
        assert_eq!(lines, vec!["a", ""]);

        string_buffer.clear();

        assert!(matches!(
            read_line_block(&mut reader, &mut string_buffer),
            ReadLinesResult::Ok
        ));
        let lines: Vec<_> = string_buffer.lines().collect();
        assert_eq!(lines, vec!["b", ""]);
    }
}
