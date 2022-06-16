use crate::*;

#[test]
fn test_list_entries() {
    env::set_var(
        "PASSWORD_STORE_DIR",
        env::current_dir().unwrap().join("tests/simple"),
    );
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
            StoreEntry::Directory {
                path: PASSWORD_STORE_DIR.join("folder"),
                content: vec![
                    StoreEntry::File(StoreFileRef {
                        path: PASSWORD_STORE_DIR.join("folder/subsecret-a.gpg")
                    }),
                    StoreEntry::File(StoreFileRef {
                        path: PASSWORD_STORE_DIR.join("folder/subsecret-b.gpg")
                    }),
                    StoreEntry::Directory {
                        path: PASSWORD_STORE_DIR.join("folder/subfolder"),
                        content: vec![
                            StoreEntry::File(StoreFileRef {
                                path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-a.gpg"),
                            }),
                            StoreEntry::File(StoreFileRef {
                                path: PASSWORD_STORE_DIR.join("folder/subfolder/generated-b.gpg"),
                            })
                        ]
                    }
                ]
            },
            StoreEntry::Directory {
                path: PASSWORD_STORE_DIR.join("folder2"),
                content: vec![StoreEntry::File(StoreFileRef {
                    path: PASSWORD_STORE_DIR.join("folder2/subsecret-a.gpg")
                })]
            }
        ]
    );
}

#[test]
fn test_retrieve_entry() {
    env::set_var(
        "PASSWORD_STORE_DIR",
        env::current_dir().unwrap().join("tests/simple"),
    );

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
