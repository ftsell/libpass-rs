//! General utilities used internally

use std::io;
use std::path::Path;
use std::path::PathBuf;

use directories::UserDirs;
use lazy_static::lazy_static;

/// Expand `~` in a path and canonicalize it afterwards
pub(crate) fn canonicalize_path<P: AsRef<Path>>(path: &P) -> io::Result<PathBuf> {
    let path = path.as_ref();

    if !path.starts_with("~") {
        return Ok(path.into());
    }

    lazy_static! {
        static ref HOME_DIR: PathBuf = UserDirs::new().unwrap().home_dir().to_path_buf();
    }

    let home_resolved = HOME_DIR.join(path.strip_prefix("~").unwrap());
    home_resolved.canonicalize()
}
