# `dcap-cairo-cli`

A command line tool for pre-processing test data from [`dcap-rs`](https://github.com/automata-network/dcap-rs) to be used in [`dcap-cairo`](https://github.com/cartridge-gg/dcap-cairo).

> [!NOTE]
>
> In its current form, the CLI is only designed to handle test data for demonstration purposes. The goal is to show that `dcap-cairo` is capable of verifying the exact same quote that `dcap-rs` is testing against.
>
> Once `dcap-cairo` ships a full contract-based verification system, however, this CLI shall be updated to include full functionalities including calldata preperation.

This CLI exists because:

- Cairo does not have a built-in macro equivalent for Rust's `include_bytes!`.
- Certain operations like base-64 and hex decoding are wasteful to be done in Cairo.
- JSON data are better represented as structured data to avoid JSON parsing in Cairo.

## Installation

To install the `dcap-cairo` command:

```console
cargo install --locked --path .
```

## Usage

Once installed, the following commands are available:

- `dcap-cairo`
  - `preprocess`
    - `quote`: Pre-process quote to convert cert chain from PEM to DER format.
    - `pem`: Pre-process PEM-encoded file to convert to DER format in the form of Cairo byte array definition.
    - `include-bytes`: Pre-process any file to be interpreted as binary as defined as Cairo byte array.
    - `qeidentity`: Pre-process qeidentity JSON file to convert to Cairo struct definition.
    - `tcbinfo`: Pre-process tcbinfo JSON file to convert to Cairo struct definition.

For example, to create a Cairo file containing the byte array definition of this very `README.md` file:

```console
dcap-cairo preprocess include-bytes --input ./README.md --output ./readme.cairo
```

The command above would generate a `readme.cairo` file containing a `pub` definition of a `DATA` constant similar to:

```cairo
pub const DATA: [u8; 1709] = [
    0x23, 0x20, 0x60, 0x64, 0x63, 0x61, 0x70, 0x2d, 0x63, 0x61, 0x69, 0x72, 0x6f, 0x2d, 0x63, 0x6c,
    0x69, 0x60, 0xa, 0xa, 0x41, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x6c, 0x69,
...
```

This file can then be used as a Cairo module to be used in the rest of the codebase.
