# hashdex web

A static page that resolves content hashes the way `hdx` does — drop a
file (hashed locally, never uploaded) or paste a hash, and see where
those bytes already live on the public web. Lookups are HTTP range
reads from the browser into hashdex's published datasets on Hugging
Face: k×8-byte probes into the DCSO bloom filters and page-indexed
parquet point lookups for fatcat attributions. There is no server
component; a `#sha256:…` URL fragment makes results shareable without
the hash ever reaching a server.

## Build

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli   # version matching Cargo.lock's wasm-bindgen
./build.sh                       # emits pkg/
```

Serve the directory statically (`python3 -m http.server`) — `pkg/` and
`index.html` are the whole deployment.

This crate is deliberately not a workspace member of the published
`hashdex` crate; it depends on it by path with
`default-features = false` (the core that compiles for wasm32).
