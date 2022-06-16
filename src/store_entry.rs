//! Type definitions and interaction logic for entries in a password store

use crate::{utils, PassError, Result};
use std::collections::HashSet;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::PathBuf;

/// An entry in the password store
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum StoreEntry {
    /// A reference to a directory which contains other entries
    Directory(StoreDirectoryRef),
    /// A reference to a file that holds the actual content of a store
    File(StoreFileRef),
}

impl StoreEntry {
    /// Retrieve the name of the store entry
    ///
    /// The name is represented as a relative path from the store root and can be used to retrieve this
    /// entry using [`retrieve`](crate::retrieve).
    pub fn name(&self) -> Result<String> {
        match self {
            Self::Directory(dir) => dir.name(),
            Self::File(file) => file.name(),
        }
    }

    /// Verify that this store entry matches what is actually present on the filesystem
    pub(crate) fn verify(&self) -> Result<()> {
        match self {
            Self::Directory(dir) => dir.verify(),
            Self::File(file) => file.verify(),
        }
    }
}

/// A reference to a directory in the password store
#[derive(Debug, Eq, Clone)]
pub struct StoreDirectoryRef {
    /// Absolute path to the referenced directory
    pub path: PathBuf,
    /// Other entries that are contained in this directory
    pub content: HashSet<StoreEntry>,
}

impl StoreDirectoryRef {
    /// Retrieve the name of the store entry
    ///
    /// The name is represented as a relative path from the store root and can be used to retrieve this
    /// entry using [`retrieve`](crate::retrieve).
    pub fn name(&self) -> Result<String> {
        Ok(utils::path2str(utils::abspath2relpath(&self.path)?)?.to_string())
    }

    /// Verify that *self* references an existing directory
    pub(crate) fn verify(&self) -> Result<()> {
        if self.path.exists() && self.path.is_dir() {
            Ok(())
        } else {
            Err(PassError::InvalidStoreFormat(
                self.path.to_owned(),
                "Path either does not exist or is not a directory".to_string(),
            ))
        }
    }
}

impl Hash for StoreDirectoryRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl PartialEq for StoreDirectoryRef {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

/// A reference to a file in the password store
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct StoreFileRef {
    /// Absolute path to the referenced directory
    pub path: PathBuf,
}

impl StoreFileRef {
    /// Retrieve the name of the store entry
    ///
    /// The name is represented as a relative path from the store root and can be used to retrieve this
    /// entry using [`retrieve`](crate::retrieve).
    pub fn name(&self) -> Result<String> {
        let relative_path = utils::path2str(utils::abspath2relpath(&self.path)?)?;

        Ok(relative_path
            .strip_suffix(".gpg")
            .ok_or_else(|| {
                PassError::InvalidStoreFormat(
                    self.path.to_owned(),
                    "File does not end with .gpg extension".to_string(),
                )
            })?
            .to_string())
    }

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

    /// Verify that *self* references an existing file with the expected file extension
    pub(crate) fn verify(&self) -> Result<()> {
        if self.path.exists()
            && self.path.is_file()
            && match self.path.extension() {
                None => false,
                Some(extension) => extension == "gpg",
            }
        {
            Ok(())
        } else {
            Err(PassError::InvalidStoreFormat(self.path.to_owned(), "Path either does not exist, is not a regular file or does not have a .gpg extension".to_string()))
        }
    }
}
