//! Different handles and utilities for working file files

use crate::{utils, Result};

use std::fs::File;
use std::io::Read;
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
/// ## Usage
/// This handle decrypts the entries content into an internal buffer when it is created.
/// That buffer is intended as the access point to the decrypted content via `AsRef<[u8]>` and `AsMut<[u8]>`.
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
/// let content = plain_file.as_ref();
/// assert_eq!(content, "foobar123\n".as_bytes());
/// ```
#[derive(Debug)]
pub struct PlainFile {
    file: File,
    buffer: Vec<u8>,
}

impl PlainFile {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        let mut result = Self {
            file: File::options()
                .read(true)
                .write(true)
                .create(false)
                .open(path)?,
            buffer: Vec::with_capacity(path.metadata()?.len() as usize),
        };
        result.load_and_decrypt()?;
        Ok(result)
    }

    /// Load the content from filesystem and decrypt it into the internal buffer
    fn load_and_decrypt(&mut self) -> Result<()> {
        let mut ciphertext = Vec::with_capacity(self.file.metadata()?.len() as usize);
        self.file.read_to_end(&mut ciphertext)?;

        let mut gpg_ctx = utils::create_gpg_context()?;
        gpg_ctx.decrypt(&mut ciphertext, &mut self.buffer)?;

        Ok(())
    }

    // Encrypt the internal buffer and store it in the file
    // fn encrypt_and_store(&self) -> Result<()> {
    //     todo!("Writing back to the file is not yet implemented")
    // }
}

impl AsRef<[u8]> for PlainFile {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsMut<[u8]> for PlainFile {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

// impl Drop for PlainFile {
//     fn drop(&mut self) {
//         if let Err(e) = self.encrypt_and_store() {
//             log::warn!(
//                 "Error during drop of PlainFile, could not store encrypted content in file: {:?}",
//                 e
//             )
//         }
//     }
// }
