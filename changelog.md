<!--
This changelog file is intended to be updated during development and is automatically cleared after
a release
-->

## Notable Changes

- **Breaking Change:** `PlainFile` handles previously implemented `AsRef<[u8]>` which has been changed to
    `AsRef<Vec<u8>>` to allow easier mutation.
- **Addition**: Add `StoreFileRef::encryption_keys()` function to retrieve the keys used for encrypting the given
    file.
- **Addition**: Writing content of encrypted files is now implemented and properly synchronizes back to the underlying
    file.
