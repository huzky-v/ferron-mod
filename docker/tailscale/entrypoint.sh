#!/bin/sh
# Ferron owns managed tailscaled children; exec preserves signal delivery.
set -eu
export TS_MANAGED_TAILSCALE=1
exec /usr/local/bin/ferron "$@"
