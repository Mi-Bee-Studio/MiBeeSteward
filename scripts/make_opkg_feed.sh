#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
#
# This file is part of MiBee Steward, distributed under the GNU Affero General
# Public License v3.0 or later. See LICENSE for the full text. A commercial
# license is available for use cases the AGPL does not accommodate; see
# LICENSE-COMMERCIAL.md.

# Build an opkg feed directory from a set of .ipk packages (#563).
#
# Usage: scripts/make_opkg_feed.sh <pkg-dir> <out-dir>
#
# Scans <pkg-dir>/*.ipk, extracts each package's control metadata, and writes
# the opkg-standard index (<out-dir>/Packages + Packages.gz) alongside copies
# of the packages. The result is a self-contained directory any static file
# server can host; a router subscribes with:
#   echo "src/gz mibee http://<host>/<path>/" >> /etc/opkg/customfeeds.conf
#   opkg update
#
# Trust model: every stanza carries SHA256sum, so opkg verifies each download
# against the index it fetched over the same channel. The index itself is
# unsigned (usign/ed25519 signing is a follow-up): serve it from a LAN host
# or HTTPS origin you control, the same trust you already place in the
# release artifacts.
#
# Works with GNU and busybox tar; needs a gzip. Runs on the build host.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <pkg-dir> <out-dir>" >&2
  exit 1
fi

src_dir="${1%/}"
out_dir="${2%/}"

shopt -s nullglob
ipks=("$src_dir"/*.ipk)
if [[ ${#ipks[@]} -eq 0 ]]; then
  echo "no .ipk packages found in $src_dir" >&2
  exit 1
fi

mkdir -p "$out_dir"
index="$out_dir/Packages"
: > "$index"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for ipk in "${ipks[@]}"; do
  base="$(basename "$ipk")"
  cp "$ipk" "$out_dir/$base"

  # The ipk is a gzip tar of (./debian-binary, ./control.tar.gz, ./data.tar.gz);
  # dig out the control member, then the control file inside it. The members
  # carry a ./ prefix, so extract unfiltered rather than by member name.
  rm -rf "$work/x"
  mkdir -p "$work/x"
  tar -xzf "$ipk" -C "$work/x"
  tar -xzf "$work/x/control.tar.gz" -C "$work/x" ./control 2>/dev/null \
    || tar -xzf "$work/x/control.tar.gz" -C "$work/x" control
  ctrl="$work/x/control"
  if [[ ! -f "$ctrl" ]]; then
    echo "::error::no control member in $base" >&2
    exit 1
  fi

  size=$(wc -c < "$ipk" | tr -d ' ')
  sha=$(sha256sum "$ipk" | awk '{print $1}')

  # Copy the control stanzas through, then append the feed fields opkg
  # resolves relative to the index location.
  cat "$ctrl" >> "$index"
  printf 'Filename: %s\nSize: %s\nSHA256sum: %s\n' "$base" "$size" "$sha" >> "$index"
  printf '\n' >> "$index"
done

gzip -9 -c "$index" > "$out_dir/Packages.gz"

pkgs=$(grep -c '^Package:' "$index" || true)
echo "feed index: $out_dir/Packages ($pkgs packages)"
echo "host it with e.g.:  python3 -m http.server --directory '$out_dir'"
