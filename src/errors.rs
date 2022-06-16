#[cfg(nightly)]
use std::backtrace::Backtrace;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that may returned by library functions
#[derive(Error, Debug)]
pub enum PassError {
    /// Indication that there doesn't exist a password store at a given location
    #[error("No password store was found at {0}")]
    PasswordStoreNotFound(PathBuf),

    /// The on-disk password store is somehow incorrectly formatted
    #[error("The pass store at {0} is incorrectly formatted: {1}")]
    InvalidStoreFormat(PathBuf, String),

    /// The requested entry could not be clearly identified because it is ambiguous
    #[error("Password name {0} is ambiguous because it references a directory as well as a file inside the store")]
    AmbiguousPassName(String),

    /// The requested entry was not found in the password store
    #[error("The requested entry ({0}) was not found in the password store")]
    EntryNotFound(String),

    /// An on-disk path could not be correctly interpreted by this program
    ///
    /// This can happen because rust imposes that all strings must be valid UTF-8 but some operating systems
    /// don't impose the same restrictions on their file paths.
    /// When trying to convert from a path (which is represented using [`OsString`](std::ffi::OsString)) to a
    /// rust string, this error is returned.
    #[error("Could not decode the path {0} as UTF-8 string")]
    PathDecodingError(PathBuf),

    /// Some IO error occurred that is preserved as `source`
    #[error("IO Error")]
    IOError {
        /// The underlying error
        #[from]
        source: io::Error,
        #[cfg(nightly)]
        backtrace: Backtrace,
    },

    /// Some error occurred during entry interaction that is preserved as `source`
    #[error("GPG error")]
    GpgError {
        /// The underlying error
        #[from]
        source: gpgme::Error,
        #[cfg(nightly)]
        backtrace: Backtrace,
    },
}
