//! General utilities used internally

use crate::{PassError, Result, PASSWORD_STORE_DIR};

use std::io;
use std::path::Path;
use std::path::PathBuf;

use directories::UserDirs;
use gpgme::{Context, Protocol};
use lazy_static::lazy_static;

/// Expand `~` in a path and canonicalize it afterwards
pub(crate) fn canonicalize_path<P: AsRef<Path>>(path: &P) -> io::Result<PathBuf> {
    let path = path.as_ref();
    lazy_static! {
        static ref HOME_DIR: PathBuf = UserDirs::new()
            .expect("Could not retrieve users home directory")
            .home_dir()
            .to_path_buf();
    }

    match path.strip_prefix("~") {
        // prefix was not found
        Err(_) => Ok(path.to_owned()),
        // prefix was stripped
        Ok(path) => HOME_DIR.join(path).canonicalize(),
    }
}

/// Create a gpgme context that is initialized as we need it
pub(crate) fn create_gpg_context() -> Result<Context> {
    Ok(Context::from_protocol(Protocol::OpenPgp)?)
}

/// Transform an absolute path to a path that is relative to the password store root
pub(crate) fn abspath2relpath(path: &Path) -> Result<&Path> {
    path.strip_prefix(&*PASSWORD_STORE_DIR).map_err(|_| {
        PassError::InvalidStoreFormat(
            path.to_owned(),
            "Path is not inside password store".to_string(),
        )
    })
}

/// Decode a path to rust string and handle error in an idiomatic way
pub(crate) fn path2str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| PassError::PathDecodingError(path.to_owned()))
}
