# WASM File Validator

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
