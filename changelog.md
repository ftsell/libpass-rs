<!--
This changelog file is intended to be updated during development and is automatically cleared after
a release
-->

## Notable Changes

- **Breaking Change**: Differentiate between read-only and read-write IO to password files.
    This breaks the existing `plain_io()` down into `plain_io_rw()` and `plain_io_ro()`.
- **Added** a new error which describes that a gpg key could not be loaded
