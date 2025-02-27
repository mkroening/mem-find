# mem-find

[![Crates.io](https://img.shields.io/crates/v/mem-find)](https://crates.io/crates/mem-find)
[![CI](https://github.com/mkroening/mem-find/actions/workflows/ci.yml/badge.svg)](https://github.com/mkroening/mem-find/actions/workflows/ci.yml)

This application searches the memory of a process (haystack) for a string (needle) via Linux' procfs.

## Example

```console
$ mem-find "Shell opt" $(pgrep bash)
Searching for "Shell opt" in process 123456 by mkroening: `bash`
55f658a30099: "Shell options:\n"
```

## Installation

This application can be installed via `cargo`:

```bash
cargo install mem-find
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
