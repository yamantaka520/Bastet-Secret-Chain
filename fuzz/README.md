# Fuzzing

Four targets, over the three places where `bsc` parses bytes it did not write:
a sealed ciphertext, a break-glass bundle, and the two JSON documents that
arrive from outside the vault (an anchor line, an export bundle).

```sh
cargo install cargo-fuzz
rustup toolchain install nightly     # -Zsanitizer is nightly-only
cargo +nightly fuzz run bundle -- -max_total_time=300
cargo +nightly fuzz list
```

`fuzz/rust-toolchain.toml` selects nightly inside this directory; the `+nightly`
above is belt and braces for when cargo is invoked from the repository root,
where the pin is stable.

CI runs every target for a bounded time on each push to `main` and for longer
on a weekly schedule; a crash is uploaded as an artifact and fails the job.

**Invariant under test: none of these may panic, hang, or allocate without
bound.** They are all allowed — expected, mostly — to return an error. A
`Result::Err` is a pass. An `unwrap` on attacker-shaped input is not.

The `bundle` target clamps the KDF cost fields in the header before calling,
because otherwise every iteration would spend a second in Argon2 and the fuzzer
would explore nothing. The ceiling that rejects absurd costs is covered by an
ordinary test instead: `crates/bsc-crypto/tests/hostile.rs`.
