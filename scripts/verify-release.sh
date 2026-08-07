#!/usr/bin/env bash
set -euo pipefail

dist_dir="${1:-dist}"
expected_version="${2:-}"

if [[ ! -d "$dist_dir" || ! -f "$dist_dir/checksums.txt" ]]; then
  echo "release verification: missing distribution directory or checksums.txt" >&2
  exit 1
fi

archives=()
while IFS= read -r archive; do
  archives+=("$archive")
done < <(find "$dist_dir" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print | sort)
if [[ ${#archives[@]} -ne 6 ]]; then
  echo "release verification: expected 6 archives, found ${#archives[@]}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dist_dir" && sha256sum --check checksums.txt)
else
  (cd "$dist_dir" && shasum -a 256 --check checksums.txt)
fi

archive_names="$(mktemp)"
checksum_names="$(mktemp)"
cleanup_files() {
  rm -f "$archive_names" "$checksum_names"

  if [[ -n "${unpack_dir:-}" && -d "$unpack_dir" ]]; then
    rm -rf "$unpack_dir"
  fi
}
trap cleanup_files EXIT

printf '%s\n' "${archives[@]##*/}" | sort >"$archive_names"
awk '{print $2}' "$dist_dir/checksums.txt" | sort >"$checksum_names"
if ! cmp -s "$archive_names" "$checksum_names"; then
  echo "release verification: checksum manifest does not cover exactly the release archives" >&2
  exit 1
fi

host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64 | amd64) host_arch="amd64" ;;
  arm64 | aarch64) host_arch="arm64" ;;
  *) host_arch="unsupported" ;;
esac
ran_host_binary=false
unpack_dir=""
for archive in "${archives[@]}"; do
  unpack_dir="$(mktemp -d)"
  case "$archive" in
    *.tar.gz) tar -xzf "$archive" -C "$unpack_dir" ;;
    *.zip) unzip -q "$archive" -d "$unpack_dir" ;;
  esac

  test -s "$unpack_dir/LICENSE"
  test -s "$unpack_dir/README.md"
  test -s "$unpack_dir/THIRD_PARTY_NOTICES.md"
  binary="$unpack_dir/certpulse"
  if [[ "$archive" == *.zip ]]; then
    binary="$unpack_dir/certpulse.exe"
  fi
  test -s "$binary"

  archive_lower="$(printf '%s' "$archive" | tr '[:upper:]' '[:lower:]')"
  if [[ "$archive_lower" == *"_${host_os}_${host_arch}"* ]]; then
    version_output="$("$binary" version)"
    if [[ -z "$version_output" || "$version_output" == dev ]]; then
      echo "release verification: Linux amd64 binary has no release version" >&2
      exit 1
    fi
    if [[ -n "$expected_version" && "$version_output" != "$expected_version" ]]; then
      echo "release verification: binary version $version_output does not match $expected_version" >&2
      exit 1
    fi
    ran_host_binary=true
  fi
  rm -rf "$unpack_dir"
  unpack_dir=""
done

if [[ "$ran_host_binary" != true ]]; then
  echo "release verification: no archive matched host $host_os/$host_arch" >&2
  exit 1
fi

echo "release verification: all archives and checksums passed"
