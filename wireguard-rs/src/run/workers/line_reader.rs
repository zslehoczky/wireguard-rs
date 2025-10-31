use std::io::{BufRead, BufReader, Error, Read};

pub enum ReadNonEmptyLinesResult {
    StreamOpen(Result<(), Error>),
    StreamClosed,
}

pub fn read_non_empty_line_block<R: Read>(
    reader: &mut BufReader<R>,
    string_buffer: &mut String,
) -> ReadNonEmptyLinesResult {
    match read_lines(reader, string_buffer) {
        ReadLinesResult::Eof => {
            return ReadNonEmptyLinesResult::StreamClosed;
        }
        ReadLinesResult::Err(err) => {
            return ReadNonEmptyLinesResult::StreamOpen(Err(err));
        }
        _ => (),
    };

    ReadNonEmptyLinesResult::StreamOpen(Ok(()))
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

    let line_content_without_newline = &string_buffer[prev_len..(string_buffer.len() - 1)];

    ReadLineResult::Ok(line_content_without_newline)
}

enum ReadLinesResult {
    Ok,
    Eof,
    Err(Error),
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
            ReadLineResult::Err(err) => {
                return ReadLinesResult::Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_from_text(text: &'static str) -> (ReadNonEmptyLinesResult, String) {
        let mut reader = BufReader::new(text.as_bytes());
        let mut string_buffer = String::new();

        (
            read_non_empty_line_block(&mut reader, &mut string_buffer),
            string_buffer,
        )
    }

    #[test]
    fn eof() {
        let (result, _) = read_from_text("");

        assert!(matches!(result, ReadNonEmptyLinesResult::StreamClosed));
    }

    #[test]
    fn empty_line() {
        let (result, _) = read_from_text("\n");

        assert!(matches!(result, ReadNonEmptyLinesResult::StreamOpen(Ok(_))));
    }

    #[test]
    fn parse_two_messages() {
        const INPUT: &str = "a\n\
                            \n\
                            b\n\
                            \n";

        let mut reader = BufReader::new(INPUT.as_bytes());
        let mut string_buffer = String::new();

        assert!(matches!(
            read_non_empty_line_block(&mut reader, &mut string_buffer),
            ReadNonEmptyLinesResult::StreamOpen(Ok(_))
        ));
        assert!(matches!(
            read_non_empty_line_block(&mut reader, &mut string_buffer),
            ReadNonEmptyLinesResult::StreamOpen(Ok(_))
        ));
    }
}
