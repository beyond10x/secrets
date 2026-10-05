//! Where `read` puts a value: a new file, readable and writable by its owner only, that appears
//! whole or not at all (story:cli-read-out-file).
//!
//! The path must not exist, as anything: a regular file, a directory, or a symlink, dangling or
//! not, is refused before any backend is asked. The value is written into a temporary file in the
//! same directory, created exclusively, without following a symlink, with mode 0600, and synced;
//! the temporary file is then hard-linked to the path, which fails if anything appeared there in
//! the meantime and never replaces it, and is removed. A refusal names the rule that was broken and
//! never any part of the value.
use std::{
    fmt,
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

/// Why a value was not written.
#[derive(Debug)]
pub enum Refusal {
    /// Something is at the path already.
    Exists,
    /// The path is a symlink.
    Symlink,
    /// The path names a directory, or no file name at all.
    NotAFile,
    /// The file could not be created or written.
    Unwritable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Exists => "the --out path exists; read writes a new file only",
            Self::Symlink => "the --out path is a symlink; read never follows one",
            Self::NotAFile => "the --out path names no file",
            Self::Unwritable => "the --out file could not be created",
        })
    }
}

/// A temporary file beside the path, ready for the value; removed unless [`Pending::commit`]
/// links it into place.
pub struct Pending {
    temp: PathBuf,
    file: Option<File>,
    target: PathBuf,
}

/// The path, checked and with a temporary file created beside it.
///
/// # Errors
/// The [`Refusal`] the path breaks.
pub fn prepare(path: &Path) -> Result<Pending, Refusal> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(Refusal::Symlink),
        Ok(_) => return Err(Refusal::Exists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(Refusal::Unwritable),
    }
    let name = path.file_name().ok_or(Refusal::NotAFile)?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| Refusal::Unwritable)?;
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.{suffix}.secretsctl-tmp", std::process::id()));
    let temp = directory.join(temp_name);
    let file = create_private(&temp)?;
    Ok(Pending {
        temp,
        file: Some(file),
        target: path.to_path_buf(),
    })
}

#[cfg(unix)]
fn create_private(path: &Path) -> Result<File, Refusal> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Refusal::Unwritable)?;
    // The umask can only have narrowed 0600; set it exactly.
    if file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .is_err()
    {
        let _ = fs::remove_file(path);
        return Err(Refusal::Unwritable);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn create_private(_: &Path) -> Result<File, Refusal> {
    // No mode-0600 file can be promised here, so no value is written.
    Err(Refusal::Unwritable)
}

impl Pending {
    /// Writes `bytes`, syncs them and links the file into place.
    ///
    /// # Errors
    /// [`Refusal::Exists`] when something appeared at the path, [`Refusal::Unwritable`] otherwise.
    pub fn commit(mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let mut file = self.file.take().ok_or(Refusal::Unwritable)?;
        file.write_all(bytes).map_err(|_| Refusal::Unwritable)?;
        file.sync_all().map_err(|_| Refusal::Unwritable)?;
        drop(file);
        // A link never replaces what is at the path, so a path that appeared since `prepare`
        // fails here instead of being overwritten.
        match fs::hard_link(&self.temp, &self.target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(Refusal::Exists),
            Err(_) => Err(Refusal::Unwritable),
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temp);
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("secretsctl-out-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn a_path_that_appears_after_prepare_is_not_replaced() {
        let root = root("race");
        let path = root.join("value");
        let pending = prepare(&path).unwrap();
        fs::write(&path, b"other").unwrap();
        assert!(matches!(pending.commit(b"secret"), Err(Refusal::Exists)));
        assert_eq!(fs::read(&path).unwrap(), b"other");
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            1,
            "the temporary file stayed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_dropped_pending_leaves_nothing_behind() {
        let root = root("drop");
        drop(prepare(&root.join("value")).unwrap());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
