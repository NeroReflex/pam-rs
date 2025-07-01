pam-rs
========

Rust interface to the pluggable authentication module framework (PAM).

The goal of this library is to provide a type-safe API that can be used to
interact with PAM for both creating a module and using PAM.

The library aims to be a nearly drop-in replacement for the [pam-client](https://gitlab.com/cg909/rust-pam-client) crate:
it should provide a very similar API despite only the interface being copied due to license incompatibilities.

## 🌐 [pam-http](pam-http)

An example of using pam-rs by performing HTTP basic access auth to authenticate users.

## 🍻 [pam-sober](pam-sober)

If you aren't sober enough for basic math, you can't login!

### Credits

The contents of this repo are heavily borrowed from:

- [pam-client](https://gitlab.com/cg909/rust-pam-client)
- [tozny/rust-pam](https://github.com/tozny/rust-pam)
- [ndenev/pam_groupmap](https://github.com/ndenev/pam_groupmap)
- [beatgammit/pam-http](https://github.com/beatgammit/pam-http)
