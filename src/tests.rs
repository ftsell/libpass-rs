#![allow(clippy::unwrap_used)]

use crate::*;

fn set_store_dir() {
    env::set_var(
        "PASSWORD_STORE_DIR",
        env::current_dir().unwrap().join("tests/simple"),
    );
}

#[test]
fn test_list_entries() {
    set_store_dir();
    println!("{:#?}", list_entries().unwrap());
    assert_eq!(
        list_entries().unwrap(),
        vec![
            StoreEntry::File(StoreFileRef {
                path: PASSWORD_STORE_DIR.join("secret-a.gpg")
            }),
            StoreEntry::File(StoreFileRef {
                path: PASSWORD_STORE_DIR.join("secret-b.gpg")
            }),
            StoreEntry::Directory(StoreDirectoryRef {
                path: PASSWORD_STORE_DIR.join("folder"),
                content: vec![
                    StoreEntry::File(StoreFileRef {
                        path: PASSWORD_STORE_DIR.join("folder/subsecret-a.gpg")
                    }),
                    StoreEntry::File(StoreFileRef {
                        path: PASSWORD_STORE_DIR.join("folder/subsecret-b.gpg")
                    }),
                    StoreEntry::Directory(StoreDirectoryRef {
                        path: PASSWORD_STORE_DIR.join("folder/subfolder"),
                        content: vec![
                            StoreEntry::File(StoreFileRef {
                                path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-a.gpg"),
                            }),
                            StoreEntry::File(StoreFileRef {
                                path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-b.gpg"),
                            })
                        ]
                    })
                ]
            }),
            StoreEntry::Directory(StoreDirectoryRef {
                path: PASSWORD_STORE_DIR.join("folder2"),
                content: vec![StoreEntry::File(StoreFileRef {
                    path: PASSWORD_STORE_DIR.join("folder2/subsecret-a.gpg")
                })]
            })
        ]
    );
}

#[test]
fn test_retrieve_entry() {
    set_store_dir();
    // retrieving a secret works
    assert_eq!(
        retrieve("secret-a").unwrap(),
        StoreEntry::File(StoreFileRef {
            path: PASSWORD_STORE_DIR.join("secret-a.gpg")
        })
    );

    // retrieving a secret in subfolders works
    assert_eq!(
        retrieve("folder/subfolder/generated-a").unwrap(),
        StoreEntry::File(StoreFileRef {
            path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-a.gpg")
        })
    );

    // retrieving not existing secrets returns an error but does not panic
    assert!(retrieve("not-existing-folder/not-existing-secret").is_err());

    // retrieving an existing folder does not work
    assert!(retrieve("folder").is_err());
    assert!(retrieve("folder/").is_err());
}

#[test]
fn test_get_content() {
    set_store_dir();
    let entry = if let StoreEntry::File(file) = retrieve("secret-a").unwrap() {
        file
    } else {
        panic!("not a file")
    };

    assert!(entry.get_ciphertext().is_ok());
    assert_eq!(entry.get_plaintext().unwrap(), "foobar123\n".as_bytes());
}

#[test]
fn test_get_entry_name() {
    set_store_dir();

    // simple file
    assert_eq!(
        StoreEntry::File(StoreFileRef {
            path: PASSWORD_STORE_DIR.join("secret-a.gpg")
        })
        .name()
        .unwrap(),
        "secret-a"
    );

    // simple directory
    assert_eq!(
        StoreEntry::Directory(StoreDirectoryRef {
            path: PASSWORD_STORE_DIR.join("folder"),
            content: vec![],
        })
        .name()
        .unwrap(),
        "folder"
    );

    // file in subdirectory
    assert_eq!(
        StoreEntry::File(StoreFileRef {
            path: PASSWORD_STORE_DIR.join("folder/subsecret-a.gpg"),
        })
        .name()
        .unwrap(),
        "folder/subsecret-a"
    );

    // directory in subdirectory
    assert_eq!(
        StoreEntry::Directory(StoreDirectoryRef {
            path: PASSWORD_STORE_DIR.join("folder/subfolder"),
            content: vec![],
        })
        .name()
        .unwrap(),
        "folder/subfolder"
    );
}
