use crate::errors::PassError;
use crate::store_entry::StoreFileRef;
use lazy_static::lazy_static;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{env, fs};
use store_entry::StoreEntry;

mod errors;
mod store_entry;
#[cfg(test)]
mod tests;
mod utils;

/// Error type used by *libpass*.
/// Equivalent to `Result<T, PassError>`.
pub type Result<T, E = PassError> = core::result::Result<T, E>;

lazy_static! {
    pub static ref PASSWORD_STORE_DIR: PathBuf = {
        let path = match env::var("PASSWORD_STORE_DIR") {
            Ok(env_var) => Path::new(&env_var).to_path_buf(),
            Err(_) => Path::new("~/.password-store").to_path_buf(),
        };
        utils::canonicalize_path(&path).expect("Could not canonicalize PASSWORD_STORE_DIR path")
    };
}

/// List all entries in the password store
pub fn list_entries() -> Result<Vec<StoreEntry>> {
    /// function that is called recursively for each found folder and performs the actual enumeration
    fn list_and_map_folder(path: impl AsRef<Path>) -> Result<Vec<StoreEntry>> {
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
                        Ok(StoreEntry::Directory {
                            content: list_and_map_folder(&path)?,
                            path: path.clone(),
                        })
                    } else {
                        Err(PassError::InvalidStoreFormat(
                            path.clone(),
                            "File is neither a string nor directory but pass stores can only contain those types of files".to_string())
                        )
                })
            .collect()
    }

    list_and_map_folder(&*PASSWORD_STORE_DIR)
}

/// Decrypt and return the password named *pass_name*.
///
/// `pass_name` is a path to a password file relative to the store root
pub fn retrieve(pass_name: &str) -> Result<StoreEntry> {
    let result = StoreEntry::File(StoreFileRef {
        path: PASSWORD_STORE_DIR.join(pass_name.to_string() + ".gpg"),
    });

    if !result.is_valid_on_fs() {
        return Err(PassError::EntryNotFound(pass_name.to_string()));
    }

    Ok(result)
}
