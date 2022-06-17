<!--
This changelog file is intended to be updated during development and is automatically cleared after
a release
-->

## Notable Changes

- **Breaking Change:** The interface for reading plaintext and encrypted file content has been changed to be more
    idiomatic since the standard `Read` and `Write` traits can now be used through a specialized file handle.
- **Breaking Change:** The `PASSWORD_STORE_DIR` constant has been removed and replaced with the function
    `password_store_dir()` to accommodate processes changing their own environment at runtime.
