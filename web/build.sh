#!/bin/sh
# Build the wasm module and generate the JS glue into web/pkg/.
# Needs: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli
# (version must match the wasm-bindgen crate in Cargo.lock).
set -eu
cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript --out-dir pkg \
    target/wasm32-unknown-unknown/release/hashdex_web.wasm
ls -lh pkg/hashdex_web_bg.wasm
