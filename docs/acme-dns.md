# ACME DNS-01 with acme-dns

Ferron's `acme-dns` provider uses the acme-dns HTTP API directly, not a shell hook. Register once per challenge name and keep the registration credentials for renewals. acme-dns does **not** manage your main DNS zone: you must create the CNAME yourself before issuance.

1. Set up a trusted [acme-dns server](https://github.com/joohoi/acme-dns) with publicly reachable authoritative DNS and an HTTPS API. Register an account:

   ```sh
   curl -fsS -X POST https://auth.example.net/register
   ```

   Optionally POST `{"allowfrom":["YOUR_FERRON_IP/32"]}` with `Content-Type: application/json` to restrict update requests to your server's outbound IP. Save `username`, `password`, `subdomain`, and `fulldomain` from the response securely. **Do not call `/register` on each restart or renewal**: a new registration creates a different CNAME target.

2. At the DNS host for `example.org`, create `_acme-challenge.example.org. CNAME <fulldomain>.` (include the final dot if your DNS host expects an absolute name). For `www.example.org`, register a separate account and create `_acme-challenge.www.example.org. CNAME <that registration's fulldomain>.` Apex and `*.example.org` use the same `_acme-challenge.example.org` CNAME; acme-dns rotates two TXT values for this case. Verify the CNAME resolves publicly with `dig CNAME _acme-challenge.example.org` before starting issuance.

3. Configure the TLS ACME provider in your Ferron host (replace domains, contact, endpoint and credentials):

   ```text
   tls {
       provider acme
       contact "admin@example.org"
       challenge dns-01
       dns {
           provider acme-dns
           endpoint "https://auth.example.net/"
           username "<username from /register>"
           password "<password from /register>"
           subdomain "<subdomain from /register>"
       }
   }
   ```

   Protect the configuration file (or use Ferron's configuration interpolation to supply secrets); persist Ferron's ACME certificate cache. For multiple distinct names requiring different acme-dns registrations, use corresponding separate TLS configurations; a single `dns` block uses one registration. Avoid issuing more than two simultaneous challenges through one registration, since acme-dns keeps only two TXT values. Ferron posts the DNS-01 TXT value to `/update` with `X-Api-User` and `X-Api-Key`, waits for propagation, then asks the CA to validate. Renewal reuses the same registration and CNAME automatically. The acme-dns API has no delete endpoint, so TXT cleanup is intentionally a no-op; later updates rotate the records. Failed API updates prevent the challenge from being marked ready. Check your acme-dns server's outbound allowlist, API availability, public DNS delegation and CNAME if issuance fails.
