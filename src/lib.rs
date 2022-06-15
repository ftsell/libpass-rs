use crate::errors::PassError;
use lazy_static::lazy_static;
use std::ffi::{OsStr, OsString};
use std::fs::{DirEntry, FileType};
use std::path::{Path, PathBuf};
use std::{env, fs, io};
use typedefs::StoreEntry;

mod errors;
mod typedefs;
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

    /// Files that are ignored if they are found within the pass directory structure because they serve a special
    /// meaning and are interpreted explicitly when necessary
    static ref IGNORED_FILES: Vec<&'static OsStr> = vec![OsStr::new(".git"), OsStr::new(".gpg-id")];
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
                        Ok(StoreEntry::File {
                            path: path.clone()
                        })
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

#[cfg(test)]
#[test]
fn test_list_entries() {
    env::set_var(
        "PASSWORD_STORE_DIR",
        env::current_dir().unwrap().join("tests/simple"),
    );
    println!("{:#?}", list_entries().unwrap());
    assert_eq!(
        list_entries().unwrap(),
        vec![
            StoreEntry::File {
                path: PASSWORD_STORE_DIR.join("secret-a.gpg")
            },
            StoreEntry::File {
                path: PASSWORD_STORE_DIR.join("secret-b.gpg")
            },
            StoreEntry::Directory {
                path: PASSWORD_STORE_DIR.join("folder"),
                content: vec![
                    StoreEntry::File {
                        path: PASSWORD_STORE_DIR.join("folder/subsecret-a.gpg")
                    },
                    StoreEntry::File {
                        path: PASSWORD_STORE_DIR.join("folder/subsecret-b.gpg")
                    },
                    StoreEntry::Directory {
                        path: PASSWORD_STORE_DIR.join("folder/subfolder"),
                        content: vec![
                            StoreEntry::File {
                                path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-a.gpg"),
                            },
                            StoreEntry::File {
                                path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-b.gpg"),
                            }
                        ]
                    }
                ]
            },
            StoreEntry::Directory {
                path: PASSWORD_STORE_DIR.join("folder2"),
                content: vec![StoreEntry::File {
                    path: PASSWORD_STORE_DIR.join("folder2/subsecret-a.gpg")
                }]
            }
        ]
    );
}
