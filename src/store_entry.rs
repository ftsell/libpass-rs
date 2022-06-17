//! Type definitions and interaction logic for entries in a password store

use crate::file_io::{CipherFile, PlainFile};
use crate::{utils, PassError, Result};
use std::collections::hash_set::Iter as HashSetIter;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
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

    /// iterate over all the entries contained in the storage hierarchy below this directory
    ///
    /// **Note:** The iterator iterates over all entries even if they are in a subdirectory further down the
    /// storage hierarchy thus flattening it. If you want to iterate only over the entries contained directly
    /// in this directory, use the [`content`](StoreDirectoryRef::content) field instead.
    pub fn iter(&self) -> StoreDirectoryIter {
        StoreDirectoryIter {
            entries: self.content.iter(),
            current_dir: None,
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

impl<'a> IntoIterator for &'a StoreDirectoryRef {
    type Item = &'a StoreEntry;
    type IntoIter = StoreDirectoryIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator that iterates over [`&StoreEntries`](StoreEntry) contained in a directory and its
/// subdirectories
#[derive(Debug)]
pub struct StoreDirectoryIter<'a> {
    entries: HashSetIter<'a, StoreEntry>,
    current_dir: Option<Box<StoreDirectoryIter<'a>>>,
}

impl<'a> Iterator for StoreDirectoryIter<'a> {
    type Item = &'a StoreEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match self.current_dir {
            Some(ref mut entry) => match entry.next() {
                Some(next_entry) => Some(next_entry),
                None => {
                    self.current_dir = None;
                    self.next()
                }
            },
            None => match self.entries.next() {
                Some(next_entry) => match next_entry {
                    StoreEntry::File(_) => Some(next_entry),
                    StoreEntry::Directory(dir) => {
                        self.current_dir = Some(Box::new(dir.iter()));
                        self.next()
                    }
                },
                None => None,
            },
        }
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

    /// Get an IO handle to the encrypted content of this file
    pub fn cipher_io(&self) -> Result<CipherFile> {
        CipherFile::new(&self.path)
    }

    /// Get an IO handle to the plaintext content of this file
    pub fn plain_io(&self) -> Result<PlainFile> {
        PlainFile::new(&self.path)
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
