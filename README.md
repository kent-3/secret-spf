# secret-spf

_Inspired by [phoenix-spf](https://github.com/smherwig/phoenix-spf). `spf` is short for "SGX page fault" (measurement tool)._

## Build and Run

To build and run the `secret-spf` tool locally, follow these steps:

```sh
cargo build --release
sudo ./target/release/secret-spf
```

## Optional: Build with Docker

If you need to target a system with a different libc version than the one available locally, you can use Docker for building the project. This method ensures compatibility with different system environments.

### Prerequisites

Make sure you have cargo-make installed:

```sh
cargo install cargo-make
```

### Build Using Docker

To build the project using Docker, run the following command:

```sh
cargo make docker-build
```

### Target Specific libc Versions

- Ubuntu 20.04 (Focal Fossa): Use the rust:bullseye Docker image.
- Ubuntu 22.04 (Jammy Jellyfish): Use the rust:bookworm Docker image.

These images ensure that your build is compatible with the specified versions of glibc.
