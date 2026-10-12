# fnox for slicc: the `slicc/v1.39` patch series

This branch is [jdx/fnox](https://github.com/jdx/fnox) **v1.39.0** (`cc06c75`) with the patches seven needs. Each patch is one commit, and the commits are the whole series: nothing else outside them changes. Upstream's LICENSE and README are untouched. fnox is MIT, and so are these patches.

## Consumers

- **[ai-ecoverse/homescoop](https://github.com/ai-ecoverse/homescoop)** `packages/wasi-fnox` builds **`@ai-ecoverse/wasi-fnox`**, fnox for seven's kernel (slicc-kernel, `wasm32-wasip1`), from a pinned commit of this branch.
- **[ai-ecoverse/fnox-build](https://github.com/ai-ecoverse/fnox-build)** builds the native **`@ai-ecoverse/fnox`** and `@ai-ecoverse/fnox-<os>-<arch>` packages from a pinned commit. It relies on the host commits 12 to 14.

## The series

### Shared: building for WASI

1. `34de2a9` **build: gate non-WASI dependencies by target.** Cloud SDKs, reqwest, rustls/rcgen, keyring, the TUI, prompts, signal handling, file locking, keepass and enpass build only off WASI.
2. `573f46a` **providers: build only age and plain for WASI.** Other providers keep their configuration variants and fail when they are used.
3. `dfb2789` **cli: compile out modules that cannot run on WASI.** These are mcp, proxy, tui, the daemon, leases and the interactive prompts.
4. `b9094a3` **wasi: take the working directory and home from the environment.** The cwd comes from `PWD` and the home from `HOME`, and the runtime is current_thread.
5. `9a1224e` **wasi: spawn `fnox exec` children through wasix-command.** `crates/wasix-command` is copied from homescoop `crates/wasix-command` at `36ae670d`.

### Seven (design: slicc-agent-plan `secrets-tokens-design.md`, revision 3; the `/dev/sealed` protocol is §3.7)

6. `ff52251` **providers: add the sealed provider for seven's vault.** `fnox_core::sealed` is the `/dev/sealed` client. It has unit tests against an in-process mock.
7. `503ffbe` **set: seal piped values and ask seven's vault on a terminal.**
   - A value on a pipe is sent with `seal`.
   - A terminal gets `request` and `status`, and Ctrl-C sends `cancel`.
   - A value on the command line and `--key-name` are refused.
8. `a40fbad` **exec: let seven's kernel hand sealed values to the command.**
   - It sends `materialize`, then spawns the resolved path with `SLICC_SEALED_TICKET`.
   - `as_file` is refused on WASI.
   - Values from other providers are passed on with a warning.
   - A missing command exits 127.
9. `88950f7` **proxy: `rules --json`, and `proxy run` with placeholders on WASI.**
10. `1cecbed` **seven: refuse what would put a value in a program, check placeholders.**
    - `sync` and `reencrypt` are refused, and decrypting an age secret fails.
    - `check` uses `placeholder` to find removed records and stale placeholders.
11. `2306456` **wasi: allow the lints that code compiled out on WASI leaves behind.**

### Host: native builds (design: slicc-jerk-design.md §5, rules 5 and 7)

12. `8b63341` **feat(proxy): take rule secrets from lease credentials and renew them (F2).**
    - A `[[proxy.rules]]` `secret` can name a lease credential of the active profile. Names resolve as in `fnox exec`: a lease credential wins over a same-name secret.
    - The running proxy renews the lease before it expires and keeps the placeholder.
    - Offered upstream to jdx/fnox.
13. `972aab4` **fix(lease): run command leases through cmd /C on Windows (F3).**
    - `credential_command` uses the same shell, and on Windows both now hand the command line to `cmd /S /C` unchanged, so quoted paths work.
    - Offered upstream to jdx/fnox.
14. `2ff03bc` **providers: offer the sealed provider only on WASI.** Native `provider add` and the setup wizard no longer list it.

Leases and the local proxy stay compiled out on WASI, so 12 and 13 change nothing there.

## Building for slicc-kernel

```sh
RUSTFLAGS="--cfg tokio_unstable" \
  cargo build --locked --release --bin fnox --target wasm32-wasip1
wasm-opt -Oz --strip-debug --enable-bulk-memory --enable-multivalue \
  --enable-reference-types --enable-nontrapping-float-to-int --enable-sign-ext \
  target/wasm32-wasip1/release/fnox.wasm -o fnox.wasm
```

- Native builds use `cargo build`. ai-ecoverse/fnox-build signs and packages them.
- The `sealed` provider still parses in native configs, but it isn't offered (14). Without `/dev/sealed`, every use of it fails with `not running in seven: /dev/sealed is missing`.

## A new upstream release

1. Branch `slicc/v<major.minor>` from the upstream tag.
2. Cherry-pick this series in order.
3. Rerun `cargo test --workspace` natively and the WASI build above.
4. Update this file's hashes.
