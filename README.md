# libbinder

Add `bind()` specific IP (interface) support for arbituary TCP programs.

## How it works?

This library hijacks `bind()` and `connect()` libc calls, and then do actual `bind()` when necessary.

It also checks `/etc/resolv.conf` so it will not hijack your DNS requests, to prevent unexpected behavior.

## Example

```bash
LD_PRELOAD=./libbinder.so BIND_ADDRESS=192.1.2.3 git clone https://target.example.com/something.git
```

## Build

It's recommended to use [`cross`](https://github.com/cross-rs/cross) to build for glibc and musl systems.

```bash
# glibc (with oldest centos, to provide compatibility)
cross build --target x86_64-unknown-linux-gnu --release
# musl, see https://github.com/rust-lang/rust/issues/59302
# YOU NEED TO INSTALL libgcc in Alpine before using!
RUSTFLAGS="-C target-feature=-crt-static" cross build --target x86_64-unknown-linux-musl --release
```

## Notes

`redhook` is modified to provide musl building support.
