#!/usr/bin/env bash
# Publish the publishable workspace crates to crates.io, in dependency order,
# skipping any crate whose version is already on the registry.
#
#   publish-crates.sh <version>
#
# CARGO_REGISTRY_TOKEN must be set in the environment.
#
# Idempotent-ish: a re-run after a partially failed release must not
# hard-fail on the half that already landed. The sparse index is the cheap
# ground truth; 404 means never published. `cargo publish` itself waits for
# each crate to appear in the index before returning, so the next crate in
# the list can always resolve its just-published dependencies.
#
# `libid-tlsn` is deliberately absent: it carries a git dependency on `tlsn`
# (unpublished upstream) and is `publish = false` — consumers take it as a
# git dependency on this repo's release tag.
set -euo pipefail

version="${1:?usage: publish-crates.sh <version>}"
: "${CARGO_REGISTRY_TOKEN:?CARGO_REGISTRY_TOKEN must be set}"

# Dependency order: crypto has no intra-workspace deps; transcript is
# standalone; attestations depends on crypto; signer dev-depends on crypto.
CRATES=(libid-crypto libid-transcript libid-attestations libid-signer)

# Sparse-index path for a crate name (all our names are >= 4 chars).
index_path() {
  local name="$1"
  printf '%s/%s/%s' "${name:0:2}" "${name:2:2}" "$name"
}

for crate in "${CRATES[@]}"; do
  published="$(curl -fsSL "https://index.crates.io/$(index_path "$crate")" | jq -r .vers || true)"
  if grep -qxF "$version" <<<"$published"; then
    echo "::notice::$crate $version is already on crates.io; skipping publish."
    continue
  fi
  echo "Publishing $crate $version"
  cargo publish -p "$crate" --token "$CARGO_REGISTRY_TOKEN"
done

echo "OK: all publishable crates are on crates.io at $version."
