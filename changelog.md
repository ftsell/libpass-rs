<!--
This changelog file is intended to be updated during development and is automatically cleared after
a release
-->

## Notable Changes

- **Breaking Change:** The interface for reading plaintext and encrypted file content has been changed to be more
    idiomatic since the standard `Read` and `Write` traits can now be used through a specialized file handle.
- **Breaking Change:** The `PASSWORD_STORE_DIR` constant has been removed and replaced with the function
    `password_store_dir()` to accommodate processes changing their own environment at runtime.
- **Breaking Change:** `libpass::list()` now returns a flat data structure instead of the whole store tree.
    Use `libpass::retrieve("/")` if you want the complete tree structure.


- **Addition**: Implement iteration over store directories
