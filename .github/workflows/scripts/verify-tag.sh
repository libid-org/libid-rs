#!/usr/bin/env bash
# Assert the single-version invariant: every crate in the workspace inherits
# `version.workspace = true`, and — when a tag is given — the workspace
# version equals the release tag.
#
#   verify-tag.sh v1.2.3   # release mode: tag == workspace version, or die
#   verify-tag.sh          # PR mode: inheritance check only, or die
#
# Run from the repository root (CI's default working directory).
set -euo pipefail

workspace_manifest="Cargo.toml"

# The only `version = "…"` line in the root manifest lives under
# [workspace.package]; crate manifests carry `version.workspace = true`.
workspace_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$workspace_manifest" | head -n1)"

if [ -z "$workspace_version" ]; then
  echo "::error::could not read a version from $workspace_manifest [workspace.package]" >&2
  exit 1
fi

echo "workspace ($workspace_manifest): $workspace_version"

# One version, everywhere: a crate pinning its own version would silently
# detach from the release tag.
status=0
for manifest in crates/*/Cargo.toml; do
  if grep -q '^version\.workspace = true$' "$manifest"; then
    echo "$manifest: inherits workspace version"
  else
    echo "::error::$manifest does not declare 'version.workspace = true' — every crate releases under the single workspace version" >&2
    status=1
  fi
done
[ "$status" -eq 0 ] || exit "$status"

# The [workspace.dependencies] entries for intra-workspace crates carry an
# explicit `version = "…"` (required for publishing path deps). Under 0.x
# semver a stale pin stops matching after a bump, so drift fails here, not on
# release day.
while IFS= read -r line; do
  dep_version="$(sed -n 's/.*version = "\([^"]*\)".*/\1/p' <<<"$line")"
  if [ "$dep_version" != "$workspace_version" ]; then
    echo "::error::intra-workspace dependency pin out of date in $workspace_manifest: '$line' (workspace is $workspace_version)" >&2
    status=1
  fi
done < <(grep -E '^libid-[a-z-]+ = \{ path = "crates/' "$workspace_manifest")
[ "$status" -eq 0 ] || exit "$status"

if [ "$#" -ge 1 ]; then
  tag="$1"
  case "$tag" in
    v[0-9]*) ;;
    *)
      echo "::error::release tag '$tag' does not look like v<semver> (e.g. v1.2.3)" >&2
      exit 1
      ;;
  esac
  tag_version="${tag#v}"
  echo "tag:       $tag_version (from $tag)"
  if [ "$tag_version" != "$workspace_version" ]; then
    echo "::error::release tag $tag ($tag_version) does not match the workspace version ($workspace_version) — retag, or bump [workspace.package] version first" >&2
    exit 1
  fi
fi

echo "OK: versions agree."
