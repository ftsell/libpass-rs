# libpass-rs

[![Branch Status](https://img.shields.io/github/checks-status/ftsell/libpass-rs/main?style=for-the-badge)](https://github.com/ftsell/libpass-rs)
[![crates.io version](https://img.shields.io/crates/v/libpass?style=for-the-badge)](https://crates.io/crates/libpass)
[![Docs](https://img.shields.io/docsrs/libpass?style=for-the-badge)](https://docs.rs/libpass/)
![Maintenance Status](https://img.shields.io/maintenance/yes/2022?style=for-the-badge)

> A library for interacting with [pass](https://www.passwordstore.org/) managed data

[Pass](https://www.passwordstore.org/) is a password manager popular on unix systems because of its simple design
and ease of use.
This library exists to further simplify interactions with a password store that is managed by *pass* by exposing
common interactions as safe rust functions.

## Roadmap

This library is currently very minimal and only supports the features that I needed for my own use cases.
Additional features are planned to support most reasonable use cases.

In detail, the following describes the state of each feature:
- [ ] **Initializing a password store** or a subfolder of an existing password store with a set of given keys
    While doing so, also re-encrypt all stored passwords for the given and only the given keys.
- [x] **Listing contents of a password store**
- [x] **Retrieving information** about a certain entry in a password store
- [x] **Retrieving the content** of an encrypted entry (meaning the actual password)
- [ ] **Searching** inside all decrypted files for a given string
- [ ] **Inserting or updating** the content of a given entry
- [ ] **Generating** a new password and save it
- [ ] **Removing** a given entry from the store (whole directories as well as single files)
- [ ] **Moving** a given entry to a new location in the store, re-encrypting it if the new destination
  necessitates it
- [ ] **Copying** a given entry to another location, re-encrypting it if the new destination necessitates it

**Note:** Most of these feature descriptions mirror how *pass* itself behaves during these operations
(See [pass documentation](https://git.zx2c4.com/password-store/about/#COMMANDS)).

## Installation and Usage

This library can be used like any other rust library.
Check its [crates.io page](https://crates.io/crates/libpass) and documentation at [docs.rs](https://docs.rs/libpass/).
Examples are also available [in the documentation](https://docs.rs/libpass/).
