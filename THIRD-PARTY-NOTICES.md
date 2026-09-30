# Third-party notices

Bastion's own source code is released under the [MIT License](LICENSE). The
repository also redistributes the following third-party material, each under
its own license.

## Fonts

| Font | Files | License |
|---|---|---|
| [Inter](https://github.com/rsms/inter) | `app/public/fonts/Inter.woff2`, `extension/fonts/Inter.woff2` | SIL Open Font License 1.1, see [`licenses/Inter-OFL.txt`](licenses/Inter-OFL.txt) |
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) | `app/public/fonts/JetBrainsMono.woff2`, `extension/fonts/JetBrainsMono.woff2` | SIL Open Font License 1.1, see [`licenses/JetBrainsMono-OFL.txt`](licenses/JetBrainsMono-OFL.txt) |

## Public Suffix List

`extension/lib/psl-data.js` is generated from the
[Public Suffix List](https://publicsuffix.org/list/) maintained by Mozilla and
its contributors. The list data is subject to the terms of the
[Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). The original source
is available at <https://publicsuffix.org/list/public_suffix_list.dat>.

## Dependencies

Rust crates and npm packages are not vendored in this repository. They are
resolved from `Cargo.lock` and `app/package-lock.json` at build time and remain
under their respective licenses.
