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
    File {
        /// Path to the referenced directory relative to the store root
        path: PathBuf,
    },
}

impl StoreEntry {
    pub fn name(&self) -> &str {
        match self {
            StoreEntry::Directory { path, .. } => path.file_name().unwrap().to_str().unwrap(),
            StoreEntry::File { path } => path.file_name().unwrap().to_str().unwrap(),
        }
    }
}
