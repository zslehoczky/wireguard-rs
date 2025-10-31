use std::io::{self, BufWriter, Write};

use crate::uapi::ConfigError;

pub fn write_config_response<W: Write>(
    writer: &mut BufWriter<W>,
    result: Result<Option<String>, ConfigError>,
) -> io::Result<()> {
    let mut errno = 0;

    let response = match result {
        Ok(response) => response.expect("None case was already handled"),
        Err(err) => {
            log::error!("Error during config operation: {err}");

            errno = err.errno();

            String::new()
        }
    };

    writer.write_all(response.as_bytes())?;
    writer.write_all(format!("errno={errno}\n\n").as_bytes())?;

    Ok(())
}
