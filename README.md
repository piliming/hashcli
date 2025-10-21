# hashcli

A small command-line utility written in [Zig](https://ziglang.org/) for calculating cryptographic hashes (MD5, SHA1, SHA256, SHA512) from strings, files, or encoded data.  

> ⚠️ **Note:** This project was created primarily as a learning exercise for the Zig programming language. It is not intended for production use.

## Features

- Calculate hashes for:
  - Strings
  - Files
  - Hex-encoded input
  - Base64-encoded input
- Simple command-line interface
- Case-insensitive subcommands for convenience

## Usage

```bash
# Hash a string using MD5
hashcli md5 -s string "Hello World"

# Hash a file using SHA256
hashcli sha256 -s file ./example.txt

# Hash a hex-encoded input using SHA1
hashcli sha1 -s hex "68656c6c6f"

# Hash a base64-encoded input using SHA512
hashcli sha512 -s base64 "SGVsbG8gV29ybGQ="