//! Where `put` takes a value from: a hidden prompt on a terminal, a pipe on stdin, or a file only
//! its owner can access. Never the command line, and never a regular file redirected onto stdin,
//! whose permissions nobody checked.
//!
//! A refusal names the rule that was broken and never any part of the value.
use std::{
    fmt,
    fs::File,
    io::{self, IsTerminal as _, Read as _},
    path::Path,
};

use zeroize::Zeroizing;

/// Why a value was not read.
#[derive(Debug)]
pub enum Refusal {
    /// The file can be read or written by its group or by others.
    Exposed,
    /// The path is not a regular file.
    NotAFile,
    /// Stdin is neither a terminal nor a pipe.
    UncheckedStdin,
    /// The file or stdin could not be read.
    Unreadable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Exposed => {
                "the file is accessible to its group or to others; make it readable by its owner \
                 only (chmod 600)"
            }
            Self::NotAFile => "the path is not a regular file",
            Self::UncheckedStdin => {
                "stdin is neither a terminal nor a pipe; pipe the value in, type it at the \
                 prompt, or pass --file with a mode-0600 file"
            }
            Self::Unreadable => "the value could not be read",
        })
    }
}

/// At most `limit` bytes of `reader`, plus one more so a caller can tell an over-long value.
fn bounded(reader: impl io::Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let mut bytes = Zeroizing::new(Vec::new());
    let bound = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(bound)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Unreadable)?;
    Ok(bytes)
}

/// The contents of a regular file accessible to its owner only, at most `limit` bytes plus one.
pub fn read_protected(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    #[allow(unused_mut)]
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // A FIFO would otherwise block the open until a writer appears, before the regular-file
        // check below can refuse it; on a regular file the flag changes nothing.
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| Refusal::Unreadable)?;
    let metadata = file.metadata().map_err(|_| Refusal::Unreadable)?;
    if !metadata.is_file() {
        return Err(Refusal::NotAFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Refusal::Exposed);
        }
    }
    bounded(file, limit)
}

/// Whether stdin is a pipe: a FIFO, or a socket as some process spawners use for one.
#[cfg(unix)]
fn stdin_is_pipe() -> bool {
    use std::os::{fd::AsFd as _, unix::fs::FileTypeExt as _};
    let Ok(descriptor) = io::stdin().as_fd().try_clone_to_owned() else {
        return false;
    };
    File::from(descriptor).metadata().is_ok_and(|metadata| {
        let kind = metadata.file_type();
        kind.is_fifo() || kind.is_socket()
    })
}

#[cfg(not(unix))]
fn stdin_is_pipe() -> bool {
    false
}

/// Drops one trailing `\n` or `\r\n`, which `echo` and editors add.
fn trim_newline(bytes: &mut Zeroizing<Vec<u8>>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

/// The value for `put`, at most `limit` bytes plus one: from `file` when given, otherwise from a
/// hidden prompt when stdin is a terminal, otherwise from stdin when it is a pipe.
pub fn read(
    file: Option<&Path>,
    raw: bool,
    prompt: &str,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let mut bytes = if let Some(path) = file {
        read_protected(path, limit)?
    } else if io::stdin().is_terminal() {
        let typed =
            Zeroizing::new(rpassword::prompt_password(prompt).map_err(|_| Refusal::Unreadable)?);
        return Ok(Zeroizing::new(typed.as_bytes().to_vec()));
    } else if stdin_is_pipe() {
        bounded(io::stdin().lock(), limit)?
    } else {
        return Err(Refusal::UncheckedStdin);
    };
    if !raw {
        trim_newline(&mut bytes);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_trailing_newline_is_dropped_and_no_more() {
        for (given, kept) in [
            (&b"value\n"[..], &b"value"[..]),
            (b"value\r\n", b"value"),
            (b"value\n\n", b"value\n"),
            (b"value", b"value"),
            (b"", b""),
        ] {
            let mut bytes = Zeroizing::new(given.to_vec());
            trim_newline(&mut bytes);
            assert_eq!(bytes.as_slice(), kept);
        }
    }

    #[test]
    fn a_reader_is_read_to_one_byte_past_the_limit() {
        let bytes = bounded(&[7_u8; 10][..], 4);
        assert!(bytes.is_ok_and(|bytes| bytes.len() == 5));
    }
}
