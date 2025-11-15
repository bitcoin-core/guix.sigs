# Copilot Instructions for `guix.sigs`

**Repository Role**
- This repo only tracks Guix attestation artifacts for Bitcoin Core releases; expect structured data rather than typical source code.
- Binaries are never committed—only SHA256 manifest files and their armored signatures.

**Directory Conventions**
- Release folders follow `/<version>/<signer>/` (for example `30.0/jonasott/`) and must contain pairs of `noncodesigned.SHA256SUMS`/`all.SHA256SUMS` plus their `.asc` signatures.
- Keep every attestation file ASCII-only; tooling fails fast on non-ASCII content.
- Do not invent new filenames: the CI enforces exactly those two manifest names, and recognises only `.SHA256SUMS` + `.SHA256SUMS.asc`.

**Builder Keys**
- `builder-keys/<signer>.gpg` holds the mandatory armored public key used to verify each signer.
- When importing a new signer key, add a matching attestation in the same pull; extra keys without attestations fail CI.

**Local Validation Workflow**
- Build the Rust checker once with `cargo build --manifest-path contrib/touched-files-check/Cargo.toml` (requires `libgpgme` headers and `gpg` in `PATH`).
- Run the attestation gate locally via `cargo run --quiet --manifest-path contrib/touched-files-check/Cargo.toml -- "<base>..<head>"`; it verifies file statuses, ASCII encoding, GPG signatures, and key coverage.
- Execute the Python summary with `python contrib/shasum-summary/main.py <base>..<head>` to preview the PR comment that Cirrus/GitHub Actions will post.

**CI Signals**
- `.cirrus.yml` rebuilds the Rust checker, runs it on `HEAD~..HEAD`, and fails if unknown files, missing `.asc`, or signature problems are detected.
- `.github/workflows/shasum-summary.yml` posts a per-artifact hash agreement matrix to the PR after a successful summary run.

**Authoring Attestations**
- Follow `README.md` for the two-stage Guix process: upload `noncodesigned` outputs first, then `all` after applying detached signatures.
- Each `.SHA256SUMS` entry must keep the `hash␠␠path` format produced by `sha256sum --tag`-style tooling; avoid manual reformatting.
- Use `gpg --export --armor <signer> > builder-keys/<signer>.gpg` so the Rust checker can validate imports.

**Review Checklist Reminders**
- Confirm the touched release matches the tag being attested and that every added manifest has a matching `.asc` signature.
- Watch for missing signers in the Python summary output (`X` means the artifact line is absent for that signer).
- No automated formatting tools run here; double-check for trailing spaces or stray UTF-8 before committing.
