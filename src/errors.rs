#[cfg(nightly)]
use std::backtrace::Backtrace;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassError {
    #[error("No password store was found at {0}")]
    PasswordStoreNotFound(PathBuf),
    #[error("The pass store at {0} is incorrectly formatted: {1}")]
    InvalidStoreFormat(PathBuf, String),
    #[error("IO Error")]
    IOError {
        #[from]
        source: io::Error,
        #[cfg(nightly)]
        backtrace: Backtrace,
    },
}
