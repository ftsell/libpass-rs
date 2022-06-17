//! Library for interacting with [pass](https://www.passwordstore.org/) managed data
//!
//! # Examples
//!
//! **Note:** These examples assume that the environment variable `PASSWORD_STORE_DIR` is set to point
//! to the `tests/simple/` folder of this repository.
//!
//! - Retrieve a specific entry from the store
//!
//!   ```
//!     # std::env::set_var("PASSWORD_STORE_DIR", std::env::current_dir().unwrap().join("tests/simple"));
//!     let entry = libpass::retrieve("folder/subsecret-a").unwrap();
//!     assert_eq!(entry.name().unwrap(), "folder/subsecret-a");
//!   ```
//!
//! - Retrieve and decrypt a specific entry from the store
//!
//!   ```
//!     use libpass::StoreEntry;
//!     # std::env::set_var("PASSWORD_STORE_DIR", std::env::current_dir().unwrap().join("tests/simple"));
//!
//!     match libpass::retrieve("folder/subsecret-a").unwrap() {
//!         StoreEntry::File(entry) => {
//!             assert_eq!(entry.plain_io().unwrap().as_ref(), "foobar123\n".as_bytes())
//!         },
//!         _ => panic!()
//!     }
//!   ```
//!

#![deny(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_lifetimes,
    unused_qualifications
)]

pub use crate::errors::PassError;
pub use crate::store_entry::{StoreDirectoryRef, StoreEntry, StoreFileRef};
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{env, fs};

mod errors;
pub mod file_io;
mod store_entry;
#[cfg(test)]
mod tests;
mod utils;

/// Custom Result that is equivalent to `Result<T, PassError>`.
pub type Result<T, E = PassError> = core::result::Result<T, E>;

lazy_static! {
    /// lazy-static that indicates the password store directory
    ///
    /// Defaults to `~/.password-store` but can be overridden by the environment variable `PASSWORD_STORE_DIR`
    /// just like [pass itself](https://git.zx2c4.com/password-store/about/#ENVIRONMENT%20VARIABLES)
    pub static ref PASSWORD_STORE_DIR: PathBuf = {
        let path = match env::var("PASSWORD_STORE_DIR") {
            Ok(env_var) => Path::new(&env_var).to_path_buf(),
            Err(_) => Path::new("~/.password-store").to_path_buf(),
        };
        utils::canonicalize_path(&path).expect("Could not canonicalize PASSWORD_STORE_DIR path")
    };
}

/// List all entries in the password store
pub fn list() -> Result<HashSet<StoreEntry>> {
    list_and_map_folder(&*PASSWORD_STORE_DIR)
}

/// Inspect the folder at *path* and recursively map it and its content to a [`StoreEntry`]
fn list_and_map_folder(path: impl AsRef<Path>) -> Result<HashSet<StoreEntry>> {
    log::trace!("Listing files in {}", PASSWORD_STORE_DIR.display());
    fs::read_dir(path)?
        // retrieve additional information about each file from filesystem
        .map(|file| match file {
            Err(e) => Err(e),
            Ok(file) => Ok((
                file.path(),
                file.path().extension().unwrap_or_else(|| OsStr::new("")).to_os_string(),
                file.file_type()?,
            )),
        })
        // rule out that any errors occurred during information retrieval
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        // filter out files without .gpg extension
        .filter(|(_, file_extension, file_type)| (file_type.is_file() && file_extension == &OsString::from("gpg") || !file_type.is_file()))
        // map to correct StoreEntry representation and recurse into subdirectories
        .map(|(path, _, file_type)|
            if file_type.is_file() {
                Ok(StoreEntry::File(StoreFileRef {
                    path: path.clone()
                }))
            } else if file_type.is_dir() {
                Ok(StoreEntry::Directory(StoreDirectoryRef{
                    content: list_and_map_folder(&path)?,
                    path: path.clone(),
                }))
            } else {
                Err(PassError::InvalidStoreFormat(
                    path.clone(),
                    "File is neither a string nor directory but pass stores can only contain those types of files".to_string())
                )
            })
        .collect()
}

/// Retrieve the stored entry identified by *pass_name*
///
/// `pass_name` is a path to a password file or directory relative to the store root
pub fn retrieve(pass_name: &str) -> Result<StoreEntry> {
    let dir_path = PASSWORD_STORE_DIR.join(pass_name);
    let file_path = PASSWORD_STORE_DIR.join(pass_name.to_string() + ".gpg");

    match (dir_path.exists(), file_path.exists()) {
        (true, true) => Err(PassError::AmbiguousPassName(pass_name.to_string())),
        (false, false) => Err(PassError::EntryNotFound(pass_name.to_string())),
        (true, false) => Ok(StoreEntry::Directory(StoreDirectoryRef {
            content: list_and_map_folder(&dir_path)?,
            path: dir_path,
        })),
        (false, true) => Ok(StoreEntry::File(StoreFileRef { path: file_path })),
    }
    .and_then(|store_entry| {
        store_entry.verify()?;
        Ok(store_entry)
    })
}
