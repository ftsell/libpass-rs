//! Type definitions and interaction logic for entries in a password store

use crate::{utils, PassError, Result, PASSWORD_STORE_DIR};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

/// An entry in the password store
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum StoreEntry {
    /// A reference to a directory which contains other entries
    Directory {
        /// Path to the referenced directory relative to the store root
        path: PathBuf,
        /// Other entries that are contained in this directory
        content: Vec<StoreEntry>,
    },
    /// A reference to a file that holds the actual content of a store
    File(StoreFileRef),
}

impl StoreEntry {
    /// Retrieve the name of the store entry
    ///
    /// The name is represented as a relative path from the store root and can be used to retrieve this
    /// entry using [`retrieve`](crate::retrieve).
    pub fn name(&self) -> Result<String> {
        let path = match self {
            StoreEntry::Directory { path, .. } => path,
            StoreEntry::File(file) => &file.path,
        };

        let relative_path = path.strip_prefix(&*PASSWORD_STORE_DIR).map_err(|_| {
            PassError::InvalidStoreFormat(
                path.to_owned(),
                "Path is not inside password store".to_string(),
            )
        })?;
        let relative_path = relative_path
            .to_str()
            .ok_or_else(|| PassError::PathDecodingError(path.to_owned()))?;

        match self {
            StoreEntry::Directory { .. } => Ok(relative_path.to_string()),
            StoreEntry::File(_) => Ok(relative_path
                .strip_suffix(".gpg")
                .ok_or_else(|| {
                    PassError::InvalidStoreFormat(
                        path.to_owned(),
                        "File does not end with .gpg extension".to_string(),
                    )
                })?
                .to_string()),
        }
    }

    /// Verify that this store entry matches what is actually present on the filesystem
    pub(crate) fn is_valid_on_fs(&self) -> bool {
        match self {
            StoreEntry::Directory { path, .. } => path.exists() && path.is_dir(),
            StoreEntry::File(file) => {
                file.path.exists()
                    && file.path.is_file()
                    && match file.path.extension() {
                        None => false,
                        Some(extension) => extension == "gpg",
                    }
            }
        }
    }
}

/// A reference to a file in the password store
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct StoreFileRef {
    /// Path to the referenced directory relative to the store root
    pub path: PathBuf,
}

impl StoreFileRef {
    /// Retrieve the encrypted files content
    pub fn get_ciphertext(&self) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path)?;
        let mut buffer = Vec::with_capacity(file.metadata()?.len() as usize);
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Retrieve and decrypt the files content
    pub fn get_plaintext(&self) -> Result<Vec<u8>> {
        let mut ciphertext = self.get_ciphertext()?;
        let mut plaintext = Vec::new();
        let mut ctx = utils::create_gpg_context()?;
        ctx.decrypt(&mut ciphertext, &mut plaintext)?;

        Ok(plaintext)
    }
}
