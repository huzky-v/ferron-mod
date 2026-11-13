# Tailscale HTTPS hosting (experimental multi-node mode)

The `runtime-tailscale` image runs one userspace tailscaled per distinct canonical
`machine.tailnet.ts.net` host, with a private state file and LocalAPI socket for
each machine. Enable MagicDNS and HTTPS certificates in the tailnet first. This
allows separate `a` and `b` nodes in the **same** tailnet alongside public ACME:

```conf
{
    default_http_port 8080
    default_https_port 8443
}

a.my-tailnet.ts.net {
    tls { provider tailscale }
    root "/var/www/a"
}

b.my-tailnet.ts.net {
    tls { provider tailscale }
    root "/var/www/b"
}

www.example.com {
    tls { provider acme }
    root "/var/www/public"
}
```

Every ts.net host **must** select a host-specific `tls { provider tailscale }`;
a global TLS provider is never inherited for these hosts. Names must be exactly
`machine.tailnet.ts.net`: malformed
names, mismatched TLS providers, and multiple tailnets are rejected. Repeated
instances of one machine share one daemon. A host-specific block such as

```conf
tls {
    provider tailscale
    socket /path/to/tailscaled.sock
}
```

instead uses an **external, unmanaged** daemon: Ferron never starts or
stops it. Explicit sockets win over inferred sockets for the same host; two
different explicit sockets conflict.

Build with `docker build --target runtime-tailscale -t ferron-tailscale .`.
Example Compose deployment:

```yaml
services:
  ferron:
    image: ferron-tailscale
    environment:
      TS_AUTHKEY: ${TS_AUTHKEY:-}
      TS_FERRON_HTTPS_PORT: "8443"
    volumes:
      - ./ferron.conf:/etc/ferron/ferron.conf:ro
      - ts-state:/var/lib/tailscale
    restart: unless-stopped
volumes:
  ts-state:
```

`TS_AUTHKEY` may be omitted entirely. A fresh node then registers
**interactively**: Ferron runs `tailscale up` without an auth key, prints the
`https://login.tailscale.com/a/...` URL to its stderr (visible with
`docker logs`), and waits up to five minutes (override with
`TS_LOGIN_TIMEOUT` in seconds) for an operator to complete the browser login.
The URL is a one-time credential, so it is written only to the container log,
never to Ferron's error diagnostics. If the wait expires, provisioning fails
and retries after 30 seconds with a fresh URL; interactive logins occupy one of
the two provisioning workers. Because retries restart `tailscaled`, each
attempt requires a new browser visit.

Ferron's public HTTP/HTTPS and ACME listeners start immediately, without
waiting for tailscaled or its certificates. Each ts.net TLS resolver initially
has **no certificate**, so handshakes for that host fail until background
provisioning completes; the certificate is then published atomically. Handshakes
never start provisioning work. A fixed pool of two workers handles at most two
nodes concurrently, with a bounded queue; failed nodes retry no sooner than 30
seconds after failure. A successful certificate is retained across reloads;
if provisioning fails after one was published, that last-good certificate is
still served. Errors and pending state are
reported through the TLS resolver's background diagnostic. This is experimental.

On shutdown, worker scheduling stops and idle workers exit; in-flight bounded
certificate or command work is not joined, and its owned daemon is killed and
reaped when the final worker-held node handle is dropped.

The Ferron process owns managed tailscaled children. Each node uses
`TS_STATE_DIR/<machine>-<tailnet>/tailscaled.state` (default
`/var/lib/tailscale`) and `TS_SOCKET_DIR/<machine>-<tailnet>.sock` (default
`/var/run/tailscale`). Each per-node directory is passed as tailscaled's
`--statedir` and stores both node state and its TLS certificate cache. Persist
the state directory. If the node is not already Running and `TS_AUTHKEY` is
set, Ferron runs `tailscale up --hostname=<machine> --accept-dns=false
--authkey=<key>`. Without `TS_AUTHKEY`, Ferron runs the same command without a
key and waits for interactive browser login (see above). For an
already Running node with a persisted generated name, Ferron invokes
`tailscale set --hostname=<machine>` to rename it. Before requesting a
certificate, Ferron waits for Running status and an exact match
for the configured full name in status `CertDomains`; `Self.DNSName` alone does
not authorize a certificate. Naming conflicts can cause Tailscale to assign a
suffix, resulting in that host's provisioning failure until an administrator
cleans up or renames the conflicting node. `TS_EXTRA_ARGS` is unsupported: it is
rejected instead of being shell-expanded. Set `TS_FERRON_HTTPS_PORT` to a valid
port (default `8443`) matching Ferron's HTTPS listener. Each daemon configures
raw TCP Serve from tailnet port 443 to `127.0.0.1:<port>`; Ferron terminates TLS.
Publish Ferron's listener separately for public sites.

The entrypoint **execs** Ferron so it receives container signals. When the
manager is dropped it forcibly kills and reaps only its owned child daemons.
Reloads retain existing nodes (nodes removed from configuration remain running
until process restart), start new ones, and reject changed sockets or an exited
owned daemon; restart Ferron after either failure. **Restart Ferron to remove
nodes or change node topology.** Concurrent tailscaled instances in one container
are experimental; confirm your tailnet policy and Tailscale version support
this deployment. Ferron retrieves certificates in the background for newly
configured hosts. Successful nodes are not periodically refreshed: there is
**no automatic certificate renewal refresh**. Reload retains the published
certificate; process restart obtains a new one. First issuance can take several
minutes. LocalAPI status requests have a 30-second timeout and certificate
requests a five-minute timeout. A timeout reports the affected operation
instead of a raw socket error.

Userspace networking does not transparently route Ferron's outgoing traffic to
tailnet peers. Use an outbound SOCKS5/HTTP proxy in supporting clients for
tailnet backends. Public backends use ordinary Docker networking. Public-domain
CNAME automation is not part of this implementation.
