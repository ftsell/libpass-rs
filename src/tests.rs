#![allow(clippy::unwrap_used)]

use crate::utils;
use crate::*;
use std::io::Read;

fn set_store_dir() {
    env::set_var(
        PASSWORD_STORE_DIR_ENV,
        env::current_dir().unwrap().join("tests/simple"),
    );
}

fn retrieve_file(pass_name: &str) -> StoreFileRef {
    if let StoreEntry::File(file) = retrieve(pass_name).unwrap() {
        file
    } else {
        panic!("not a file")
    }
}

#[test]
fn test_get_store_dir() {
    env::remove_var(PASSWORD_STORE_DIR_ENV);
    assert_eq!(
        password_store_dir().unwrap(),
        utils::canonicalize_path(&PathBuf::from("~/.password-store")).unwrap()
    );

    set_store_dir();
    assert_eq!(
        password_store_dir().unwrap(),
        env::current_dir().unwrap().join("tests/simple")
    );
}

#[test]
fn test_list_entries() {
    set_store_dir();
    println!("{:#?}", list().unwrap());
    assert_eq!(
        list().unwrap(),
        HashSet::from_iter(
            vec![
                StoreEntry::File(StoreFileRef {
                    path: password_store_dir().unwrap().join("secret-a.gpg")
                }),
                StoreEntry::File(StoreFileRef {
                    path: password_store_dir().unwrap().join("secret-b.gpg")
                }),
                StoreEntry::Directory(StoreDirectoryRef {
                    path: password_store_dir().unwrap().join("folder"),
                    content: HashSet::from_iter(
                        vec![
                            StoreEntry::File(StoreFileRef {
                                path: password_store_dir().unwrap().join("folder/subsecret-a.gpg")
                            }),
                            StoreEntry::File(StoreFileRef {
                                path: password_store_dir().unwrap().join("folder/subsecret-b.gpg")
                            }),
                            StoreEntry::Directory(StoreDirectoryRef {
                                path: password_store_dir().unwrap().join("folder/subfolder"),
                                content: HashSet::from_iter(
                                    vec![
                                        StoreEntry::File(StoreFileRef {
                                            path: password_store_dir()
                                                .unwrap()
                                                .join("folder/subfolder/generated-a.gpg"),
                                        }),
                                        StoreEntry::File(StoreFileRef {
                                            path: password_store_dir()
                                                .unwrap()
                                                .join("folder/subfolder/generated-b.gpg"),
                                        })
                                    ]
                                    .iter()
                                    .cloned()
                                )
                            })
                        ]
                        .iter()
                        .cloned()
                    )
                }),
                StoreEntry::Directory(StoreDirectoryRef {
                    path: password_store_dir().unwrap().join("folder2"),
                    content: HashSet::from_iter(
                        vec![StoreEntry::File(StoreFileRef {
                            path: password_store_dir()
                                .unwrap()
                                .join("folder2/subsecret-a.gpg")
                        })]
                        .iter()
                        .cloned()
                    )
                })
            ]
            .iter()
            .cloned()
        )
    );
}

#[test]
fn test_retrieve_entry() {
    set_store_dir();
    // retrieving a secret works
    assert_eq!(
        retrieve("secret-a").unwrap(),
        StoreEntry::File(StoreFileRef {
            path: password_store_dir().unwrap().join("secret-a.gpg")
        })
    );

    // retrieving a secret in subfolders works
    assert_eq!(
        retrieve("folder/subfolder/generated-a").unwrap(),
        StoreEntry::File(StoreFileRef {
            path: password_store_dir()
                .unwrap()
                .join("folder/subfolder/generated-a.gpg")
        })
    );

    // retrieving a folder works
    assert!(retrieve("folder").is_ok());
    assert!(retrieve("folder/").is_ok());

    // retrieving not existing things returns an error but does not panic
    assert!(retrieve("not-existing-folder").is_err());
    assert!(retrieve("not-existing-folder/not-existing-secret").is_err());
}

#[test]
fn test_read_ciphertext() {
    set_store_dir();
    let entry = retrieve_file("secret-a");

    let mut buffer = Vec::new();
    assert!(entry
        .cipher_io()
        .unwrap()
        .as_mut()
        .read_to_end(&mut buffer)
        .is_ok());
}

#[test]
fn test_read_plaintext() {
    set_store_dir();
    let entry = retrieve_file("secret-a");

    assert_eq!(entry.plain_io().unwrap().as_ref(), "foobar123\n".as_bytes());
}

#[test]
fn test_get_entry_name() {
    set_store_dir();

    // simple file

    assert_eq!(retrieve("secret-a").unwrap().name().unwrap(), "secret-a");

    // simple directory
    assert_eq!(retrieve("folder").unwrap().name().unwrap(), "folder");

    // file in subdirectory
    assert_eq!(
        retrieve("folder/subsecret-a").unwrap().name().unwrap(),
        "folder/subsecret-a"
    );

    // directory in subdirectory
    assert_eq!(
        retrieve("folder/subfolder").unwrap().name().unwrap(),
        "folder/subfolder"
    );
}
