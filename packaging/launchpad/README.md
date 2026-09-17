# Launchpad PPA publishing

Launchpad accepts signed source uploads and builds the installable packages.
The source bundle includes vendored Cargo dependencies, so the isolated builder
does not need network access to crates.io.

## One-time owner setup

1. Add an OpenPGP public key to the Launchpad account and confirm it from the
   email Launchpad sends.
2. Accept the Launchpad terms and Ubuntu Code of Conduct.
3. Create a public PPA named `shex` under the `morphym` account.
4. On the PPA **Change details** page, enable `amd64` and `arm64`.

Do not commit or share the private OpenPGP key. The upload must be signed by a
key associated with the Launchpad account; this is distinct from the APT
archive key that Launchpad creates after the first accepted upload.

## Prepare and upload from Ubuntu

Install the packaging tools:

```sh
sudo apt update
sudo apt install cargo-1.89 rustc-1.89 devscripts debhelper dput-ng
```

Build and sign the Noble source upload using the full fingerprint of the key
registered with Launchpad:

```sh
DEBSIGN_KEYID=YOUR_GPG_FINGERPRINT \
  packaging/prepare-launchpad-source.sh noble dist/launchpad
```

Upload the generated source changes file:

```sh
dput ppa:morphym/shex \
  dist/launchpad/shex_VERSION-0ubuntu1~noble1_source.changes
```

After Launchpad finishes both builds, users install without Rust:

```sh
sudo add-apt-repository ppa:morphym/shex
sudo apt update
sudo apt install shex
```

For an unsigned local packaging check, pass `--unsigned`. Unsigned bundles are
not accepted by Launchpad.
