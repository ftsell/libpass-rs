use crate::Result;
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
    pub fn secret_name(&self) -> &str {
        match self {
            StoreEntry::Directory { path, .. } => path,
            StoreEntry::File(file) => &file.path,
        }
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit_once('.')
        .unwrap()
        .0
    }

    pub(crate) fn is_valid_on_fs(&self) -> bool {
        match self {
            StoreEntry::Directory { path, .. } => path.exists() && path.is_dir(),
            StoreEntry::File(file) => file.path.exists() && file.path.is_file(),
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
    pub fn get_content(decrypt: bool) -> Result<()> {
        todo!()
    }
}
