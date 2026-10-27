# ASN and geographic blocking

The abuse module can filter ASN numbers, ISO country codes, and continent codes using separate GeoLite2 databases. For example:

```text
{
    geo_database "/var/lib/ferron/GeoLite2-Country.mmdb"
    geo_asn_database "/var/lib/ferron/GeoLite2-ASN.mmdb"
    geo_mode true
    geo_block_asn AS64500 AS64501
    geo_block_country US GB
    geo_block_continent AN
    geo_log "/var/log/ferron/geo.log"
    geo_interval "7d"
}
```

`geo_mode`, `geo_block_asn`, `geo_block_country`, `geo_block_continent`, and `geo_log` may be overridden in site blocks; an overridden list replaces the corresponding global list. Database paths, `geo_interval`, and optional HTTPS `geo_url` / `geo_asn_url` are global. Ferron downloads the two files from the Loyalsoldier GeoIP repository immediately and every seven days by default; the parent directories must already exist and be writable. The databases are fetched in the background: until the first successful download, missing databases or unknown IPs do not block traffic. Existing valid files are loaded at startup, and refresh failures retain the last good data. Existing invalid database files cause startup to fail. The definitions allowlist wins over geo filtering. An optional geo log uses the existing best-effort Apache-format writer. GeoLite data is subject to MaxMind's license and attribution requirements; check the source's terms before use. IP location and ASN attribution are not guarantees of identity or physical location.
