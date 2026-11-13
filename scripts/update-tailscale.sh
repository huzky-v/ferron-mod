#!/bin/sh
# Check the latest stable Tailscale version and update the Dockerfile pin.
#
# Usage:
#   scripts/update-tailscale.sh              Update Dockerfile if a newer
#                                            stable release exists.
#   scripts/update-tailscale.sh --check      Only report; exit 2 when the
#                                            Dockerfile is out of date.
#   scripts/update-tailscale.sh --dockerfile PATH
#                                            Operate on another Dockerfile
#                                            (mainly for testing).
#
# The version comes from https://pkgs.tailscale.com/stable/?mode=json
# ("TarballsVersion"), the same channel the image downloads tarballs from.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dockerfile="${repo_root}/Dockerfile"
check_only=0

while [ $# -gt 0 ]; do
    case "$1" in
        --check) check_only=1 ;;
        --dockerfile)
            [ $# -ge 2 ] || { echo "--dockerfile requires a path" >&2; exit 1; }
            dockerfile=$2
            shift
            ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
    shift
done

[ -f "$dockerfile" ] || { echo "Dockerfile not found: $dockerfile" >&2; exit 1; }

current=$(sed -n 's/^ARG TAILSCALE_VERSION=\(.*\)$/\1/p' "$dockerfile" | head -n 1)
if [ -z "$current" ]; then
    echo "No 'ARG TAILSCALE_VERSION=' line found in $dockerfile" >&2
    exit 1
fi

latest=$(curl -fsSL 'https://pkgs.tailscale.com/stable/?mode=json' \
    | sed -n 's/.*"TarballsVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
if ! printf '%s' "$latest" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Could not determine the latest stable Tailscale version" >&2
    exit 1
fi

if [ "$current" = "$latest" ]; then
    echo "Tailscale ${current} is up to date."
    exit 0
fi

if [ "$check_only" = 1 ]; then
    echo "Tailscale update available: ${current} -> ${latest} (Dockerfile not modified)"
    exit 2
fi

tmp=$(mktemp "${dockerfile}.update.XXXXXX")
trap 'rm -f "$tmp"' EXIT
sed "s|^ARG TAILSCALE_VERSION=.*|ARG TAILSCALE_VERSION=${latest}|" \
    "$dockerfile" > "$tmp"
mv "$tmp" "$dockerfile"
trap - EXIT
echo "Updated TAILSCALE_VERSION in ${dockerfile}: ${current} -> ${latest}"
echo "Rebuild the runtime-tailscale image to pick up the new binaries."
