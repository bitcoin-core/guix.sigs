This repository contains Guix attestations for releases of Bitcoin Core.

# Overall process

The Guix build consists of two stages:

- In the first stage (noncodesigned), people compile the binaries from source.
- Then, code signatures for Windows and MacOS are generated from the binaries that were produced in the first stage, and [distributed](https://github.com/bitcoin—core/bitcoin-detached-sigs) to the builders.
- In the second stage (all), the builders attach these code signatures.

See https://github.com/bitcoin/bitcoin/blob/master/doc/release-process.md#building on how to build the release with Guix and create an attestation.

## Directory structure

— /<version>/<signer>/ 
Build attestations for repository tag  v<version> for <— signer —>
    -noncodesigned.SHA256SUMS: Hashes of binaries produced by the first stage build for this version.
    - noncodesigned.SHA256SUMS.asc: Detached PGP signature for  noncodesigned.SHA256SUMS.
    - all.SHA256SUMS  Hashes of binaries produced by the second stage build. This covers all the binaries uploaded to the website, and is what to check released binaries against.
    - all.SHA256SUMS.asc Detached PGP signature for all.SHA256.SUMS
— builder : keys <signer>.gpg PGP keys of the signers. If you're going to do builds and contribute attestations, file a PR to add your key here.
-  contribution. Scripts used in the CI tests.
: —</JHOVAN D ESCOBIDAL/>
