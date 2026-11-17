# WASM File Validator

> [Versão em português](README.pt-BR.md)

Example repo showing how to validate untrusted compressed/image files **in the
browser** with Rust/WebAssembly, then sign and encrypt the verdict so a Go
backend can trust it.

```
browser ──upload──▶ Rust/WASM ──inspect──▶ verdict
                         │ sign (Ed25519)
                         │ seal (x25519 ECDH + XChaCha20-Poly1305)
                         ▼
                   base64 envelope ──POST /api/verify──▶ Go (chi)
                                                          decrypt + verify sig
                                                          echo trusted verdict
```

The Go server serves **all three** from one process:

| Route            | Serves                                            |
|------------------|---------------------------------------------------|
| `GET /`          | upload SPA (`web/static/index.html`)              |
| `GET /pkg/*`     | the compiled WASM artifact + JS glue              |
| `POST /api/verify` | decrypts the sealed envelope, verifies signature |

## What it detects

All checks read **headers / central-directory metadata only** — the validator
never decompresses archive bodies and never decodes image pixels, so a hostile
file can't turn validation itself into the attack.

- **ZIP bombs** — compression ratio, total declared uncompressed size, per-entry
  size, entry count, and nested archives (recursive-bomb vector).
- **JPEG** — missing EOI, data appended after EOI, and embedded
  executable/script/archive signatures (polyglot "worm" carriers).
- **GIF** — missing trailer, data appended after the trailer (GIFAR), and the
  same embedded-signature scan.
- **PDF** — `/JavaScript` + `/OpenAction` (auto-run on open), `/Launch`
  (external program), `/AA`, `/EmbeddedFile`, outbound `/URI` / `launchURL`
  (extracts the URL), and data appended after the last `%%EOF`.

Signatures scanned for: `MZ` (PE), `\x7fELF`, `PK\x03\x04` (nested zip),
`<?php`, `<script`, `#!/`, `\xca\xfe\xba\xbe`.

## ⚠️ Security note — read this

This repo embeds an **Ed25519 signing private key inside the client WASM**
because the task asked for it. **This provides no real authenticity**: the
`.wasm` is public, so anyone can extract the key and forge signatures. The
signing step here only demonstrates the mechanism.

The **encryption** direction is sound: the WASM holds only the backend's
**public** x25519 key and seals to it (anonymous-sender ECDH), so only the
backend can read the payload. That part maps to a real pattern.

For production you would instead:

- sign on a server / trusted enclave, or use per-session keys + attestation;
- treat the client verdict as a **hint**, and re-run validation server-side on
  the raw bytes before trusting it.

Because the repo is **public**, keys are generated at build time by
`cmd/genkeys` into git-ignored files (`keys_gen.rs`, `keys_gen.go`) and are
**never committed**.

## Run (Docker — recommended)

```bash
docker compose up --build
# open http://localhost:8099
```

Port `8099` is used because `8080`/`8090` are commonly taken. Change it in
`docker-compose.yml`.

## Build locally (without Docker)

Needs Go ≥1.23, Rust, and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
go mod tidy
go run ./cmd/genkeys .                 # writes keys_gen.rs + keys_gen.go
cd web/wasm && wasm-pack build --release --target web --out-dir ../static/pkg
cd ../..
go run ./cmd/server                    # http://localhost:8099
```

## Tests & coverage

Minimal test stack with an **80% coverage** gate (Go + Rust).

```bash
make keys           # generate keys_gen.* (required before testing)
make test           # Go + Rust unit tests
make cover          # 80% gate for Go and Rust (needs cargo-llvm-cov)
make cover-docker   # run the whole gate in containers, no host toolchains
```

- **Go** (`cmd/server`, `cmd/genkeys`): re-creates the seal inside the test to
  exercise `unseal`/`handleVerify`, covers routes, valid/invalid signatures and
  malformed input.
- **Rust** (`web/wasm`): tests every inspector (zip/jpeg/gif/pdf/unknown), the
  helpers, and sealing (`seal_to_backend`) natively (the `getrandom` JS backend
  is wasm-target-only, so `cargo test` runs on the host).

CI (`.github/workflows/ci.yml`) runs the same 80% gate on every push/PR.

## Limitations & evasion (read before trusting a verdict)

This is a fast **structural scanner, not a full parser**. Known gaps, and how the
code handles them:

- **PDF obfuscation.** Name hex-escapes are normalized (`/J#61vaScript` →
  `/JavaScript`) before matching, but content inside **FlateDecode / object
  streams is not inflated**. A payload hidden there evades the string scan, so
  their presence is flagged as `pdf_compressed_streams` ("inspect server-side")
  rather than silently passing. Real coverage needs a PDF parser that
  decompresses objects.
- **Recursive zip bombs.** Nested archives are detected by a bounded 4-byte
  magic probe (name-independent, so `payload.bin` is still caught), but
  detection is **single-layer** — a 42.zip-style recursive bomb needs
  depth-limited extraction with hard byte/time caps. ZIP central-directory sizes
  are **advisory**; a liar needs a capped real inflation to confirm.
- **Image end-of-file.** JPEG markers and GIF blocks are walked structurally to
  the true end (so an `FF D9` in a thumbnail or a `0x3B` data byte is not
  mistaken for the end). Truncated or nonstandard images report "no valid end
  reached" rather than guessing.
- **`decrypted` is not authentication.** The seal is anonymous-sender to a
  public key, and the signing key is extractable from the `.wasm`, so **anyone
  can craft a valid envelope**. `decrypted: true` means only "sealed to us".
  Keep real auth (session/token/mTLS) and server-side validation.
- **No replay protection.** A captured envelope re-decrypts. In production bind
  each envelope to a server-issued nonce/timestamp (as AAD) and reject repeats.

## Crypto, precisely

- **Sign:** Ed25519 over the canonical verdict JSON bytes.
- **Seal:** ephemeral x25519 keypair; `shared = X25519(eph_secret, backend_pub)`;
  `key = HKDF-SHA256(shared, info="wasm-file-validator-v1")`;
  `XChaCha20-Poly1305(key, nonce)` with the ephemeral public key as AAD.
- **Envelope:** `ephemeral_pub(32) || nonce(24) || ciphertext`, base64-encoded.

## Layout

```
cmd/genkeys/      generates keypairs + embedded-key source files
cmd/server/       chi server: SPA + wasm + /api/verify
web/wasm/         Rust crate (validation + sign + seal)
web/static/       SPA; wasm-pack output lands in web/static/pkg/
```

## License

MIT
