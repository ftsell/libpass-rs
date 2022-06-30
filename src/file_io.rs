//! Different handles and utilities for working with files

use crate::{utils, Result};

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// A file handle that operates on encrypted content
///
/// Get an instance of this by calling [`StoreFileRef::cipher_io()`](crate::StoreFileRef::cipher_io).
///
/// ## Usage
/// This handle does not implement much logic but is intended to be used via its `AsRef<File>` and
/// `AsMut<File>` implementations.
///
/// For example, if you already have a [`StoreFileRef`](crate::StoreFileRef), you can use it to interact
/// with the encrypted file content like so:
/// ```
/// # use std::io::{Read, Seek, SeekFrom, Write};
/// # use libpass::{StoreEntry};
/// # use libpass::file_io::CipherFile;
/// # std::env::set_var("PASSWORD_STORE_DIR", std::env::current_dir().unwrap().join("tests/simple"));
/// # let store_file_ref = match libpass::retrieve("secret-a").unwrap() {
/// #     StoreEntry::File(f) => f,
/// #     StoreEntry::Directory(_) => panic!()
/// # };
/// let mut cipher_file: CipherFile = store_file_ref.cipher_io().unwrap();
/// let mut buffer = Vec::new();
///
/// // read encrypted content
/// cipher_file.as_mut().read_to_end(&mut buffer).unwrap();
///
/// // write encrypted content
/// # cipher_file.as_mut().seek(SeekFrom::Start(0)).unwrap();
/// cipher_file.as_mut().write_all(&buffer).unwrap();
/// ```
#[derive(Debug)]
pub struct CipherFile {
    file: File,
}

impl CipherFile {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            file: File::options()
                .read(true)
                .write(true)
                .create(false)
                .open(path)?,
        })
    }
}

impl AsRef<File> for CipherFile {
    fn as_ref(&self) -> &File {
        &self.file
    }
}

impl AsMut<File> for CipherFile {
    fn as_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

/// A file handle that operates on plaintext file content, transparently encrypting and decrypting it.
///
/// Get an instance of this by calling [`StoreFileRef::plain_io()`](crate::StoreFileRef::cipher_io).
///
/// PlainFiles are automatically, encrypted synced and closed when they go out of scope.
/// Errors detected on closing are logged and ignored by the implementation of Drop.
/// Use the method [`PlainFile::sync()`] if these errors must be manually handled.
///
/// ## Usage
/// This handle decrypts the entries content into an internal buffer when it is created.
/// That buffer is intended as the access point to the decrypted content via `AsRef<Vec<u8>>` and `AsMut<Vec<u8>>`.
///
/// For example, if you already have a [`StoreFileRef`](crate::StoreFileRef), you can use it to interact with
/// the plaintext file content like so:
/// ```
/// # use libpass::{StoreEntry};
/// # use libpass::file_io::PlainFile;
/// # std::env::set_var("PASSWORD_STORE_DIR", std::env::current_dir().unwrap().join("tests/simple"));
/// # let store_file_ref = match libpass::retrieve("secret-a").unwrap() {
/// #    StoreEntry::File(f) => f,
/// #     _ => panic!()
/// # };
/// let mut plain_file: PlainFile = store_file_ref.plain_io().unwrap();
///
/// // read encrypted content
/// let content: &Vec<u8> = plain_file.as_ref();
/// assert_eq!(content, "foobar123\n".as_bytes());
/// ```
#[derive(Debug)]
pub struct PlainFile {
    /// The underlying file which this handle wraps
    file: File,

    /// The plaintext buffer that is exposed to the user to do their operations with
    buffer: Vec<u8>,

    /// Backup buffer containing the last-synced plaintext content.
    /// This is used to decide whether an actual sync is needed or if it can be skipped because the content
    /// has not been changed.
    last_synced_buffer: Vec<u8>,

    /// Collection of keys which are used as gpg recipients during encryption
    encryption_keys: Vec<gpgme::Key>,
}

impl PlainFile {
    pub(crate) fn new(path: &Path, encryption_keys: Vec<gpgme::Key>) -> Result<Self> {
        log::trace!("Opening {} as PlainFile", path.display());
        let mut result = Self {
            file: File::options()
                .read(true)
                .write(true)
                .create(false)
                .open(path)?,
            buffer: Vec::with_capacity(path.metadata()?.len() as usize),
            last_synced_buffer: Vec::new(),
            encryption_keys,
        };
        result.load_and_decrypt()?;
        Ok(result)
    }

    /// Load the content from filesystem and decrypt it into the internal buffer
    fn load_and_decrypt(&mut self) -> Result<()> {
        // read ciphertext from file
        log::trace!("Reading ciphertext from file");
        let mut ciphertext = Vec::with_capacity(self.file.metadata()?.len() as usize);
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_end(&mut ciphertext)?;

        // decrypt ciphertext and store it in buffer
        log::trace!("Decrypting ciphertext");
        let mut gpg_ctx = utils::create_gpg_context()?;
        gpg_ctx.decrypt(&mut ciphertext, &mut self.buffer)?;

        self.last_synced_buffer = self.buffer.clone();
        log::trace!("Ciphertext fully loaded and decrypted");
        Ok(())
    }

    /// Sync the buffer content into the file, encrypting it in the process
    ///
    /// Normally this operation only performs an actual content encryption and synchronization if necessary,
    /// meaning if the buffer has been changed from the last time it was synced.
    /// To overwrite this behaviour and to force encryption and synchronization, set `force=true`.
    pub fn sync(&mut self, force: bool) -> Result<()> {
        // only do a content synchronization if the content has actually ben changed by the user
        if !force && self.last_synced_buffer != self.buffer {
            // encrypt the local buffer
            let mut gpg_ctx = utils::create_gpg_context()?;
            let mut ciphertext = Vec::new();
            gpg_ctx.encrypt(&self.encryption_keys, &self.buffer, &mut ciphertext)?;

            // write it into the file
            self.file.seek(SeekFrom::Start(0))?;
            self.file.set_len(ciphertext.len() as u64)?;
            self.file.write_all(&ciphertext)?;
            self.last_synced_buffer = self.buffer.clone();
        }

        // also sync the internal file handle
        self.file.sync_all()?;
        Ok(())
    }
}

impl AsRef<Vec<u8>> for PlainFile {
    fn as_ref(&self) -> &Vec<u8> {
        &self.buffer
    }
}

impl AsMut<Vec<u8>> for PlainFile {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }
}

impl Drop for PlainFile {
    fn drop(&mut self) {
        if let Err(e) = self.sync(false) {
            log::warn!(
                "Error during drop of PlainFile, could not store encrypted content in file: {:?}",
                e
            )
        }
    }
}
