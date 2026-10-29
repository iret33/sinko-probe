# Changelog

## 1.1.0

This release fixes defects in 1.0.0 that produced wrong audit results, and backs every transport
with end-to-end tests.

### Fixed

- **DNS-over-HTTPS never worked.** The engine passed `session=` to `dns.asyncquery.https()`, which
  only accepts `client=`. On top of that, dnspython ≥ 2.9 requires its own `httpx2` client. Every
  DoH probe raised `TypeError`, and the catch-all handler reported it as
  `ERROR (Timeout/ServFail)`. DoH is now implemented directly on RFC 8484 over one shared
  HTTP/2 client.
- **DNS-over-TLS skipped certificate verification** (`CERT_NONE`), so a machine-in-the-middle
  passed the audit. Certificates are now verified. `--ca-file`, `--tls-server-name` and an
  explicit `--insecure` cover private CAs and IP-only certificates.
- **Bugs were disguised as DNS errors.** `except Exception` turned programming errors into
  verdicts. Only DNS, socket, TLS and HTTP failures are caught now, and they are reported as
  `ERROR (Timeout)`, `ERROR (SERVFAIL/RCODE)` or `ERROR (Transport)` with the cause.
- **Timeouts counted as false positives.** An unreachable must-allow site raised the
  false-positive rate, and timeout durations went into the latency percentiles. Errors are now
  reported separately and stay out of both.
- **Untested rates showed 100%.** Running only `--app youtube_app` reported "SafeSearch: 100%".
  Those rates now show `n/a`.
- **Policy custom lists were dead config.** `custom_blocklist` / `custom_allowlist` only
  re-labelled domains a profile already probed, so the shipped policy's `chat.roblox.com` was
  never queried. Every custom entry is now probed. Entries also cover subdomains, and the most
  specific entry wins.
- **`--cache-bust` gave meaningless results.** Random labels were added to allowed and SafeSearch
  domains too, which made them NXDOMAIN upstream (100% false positives, 0% SafeSearch). An
  upstream NXDOMAIN also counted as a block. Now only must-block domains are randomized, and an
  NXDOMAIN carrying the parent zone's SOA is reported as *inconclusive*.
- **SafeSearch markers used substring matching**, so `strict.bing.com.evil.example`, or IP
  `11.2.3.45` against marker `1.2.3.4`, counted as enforced. Names now match exactly or as a
  subdomain, and IPs match exactly.
- **Truncated UDP answers counted as blocks.** A TC answer has no records. UDP now retries over
  TCP, as real stub resolvers do.
- **Resolver hostnames failed every query** (`--server sinko.local`). Hostnames are now resolved
  first, and `tls://` hostnames are used for certificate verification.
- **`compare` crashed on DoH URLs and IPv6 addresses** (`int("//host/dns-query")`). Targets now
  accept the same forms as `--server`, each with its own transport (`udp://`, `tcp://`, `tls://`,
  `https://`).
- **"Realistic jitter" was not a burst model.** Every query slept 25–250 ms from t=0, and
  `--iterations` waves all fired at once. Each app now emits its queries as a burst with random
  gaps, and waves run one after another.
- **HTML report injection.** Target names, CNAMEs from the resolver and error text went into the
  page unescaped, so `--name "<script>…"` or a malicious CNAME ran script. Everything is escaped
  now, and a Content-Security-Policy only allows the page's own hashed script.
- **Rich markup injection.** A CNAME containing `[/]` crashed the terminal report with
  `MarkupError`, and endpoints such as `[sinko.local:53 / UDP]` disappeared from the title.
- **Telegram failures leaked the bot token.** A rejected request (e.g. a wrong chat ID) printed
  httpx's error, which includes the request URL and with it the **bot token**, to the console
  and cron logs. The token is now redacted. Alerts also moved from unescaped legacy Markdown to
  escaped HTML.
- **REFUSED by ACL counted as a block.** EDE 18 (*Prohibited*) is now an error, and an
  all-REFUSED run gets a warning.
- **`--min-score` failures exited with code 2**, the same code click uses for usage errors. The
  exit codes are now 0 OK, 1 below min score, 2 usage/config error, 3 resolver unreachable.
- **Unknown `--app` IDs were silently ignored**, which could produce an empty run. Policy and
  profile YAML typos were also ignored. Both are now errors with a clear message.
- **CI was red on the first commit.** Unpinned `ruff` picked up its new default rules (72
  findings). The code is clean now, ruff is pinned to a minor version, and formatting is checked.

### Added

- RFC 8914 Extended DNS Errors (queries now carry EDNS) as filtering evidence, plus EDNS padding
  on encrypted transports.
- `--sinkhole-ip` accepts CIDR ranges, and the report suggests a likely block-page IP it has not
  been told about.
- Full English/Arabic output for terminal, HTML and Telegram. The HTML dashboard is responsive,
  RTL-aware, light/dark, filterable without JavaScript, searchable and sortable.
- `ai_chatbots` profile. The bundled Homework Mode policy blocks it.
- `--version`, `python -m sinko_probe`, `list-profiles --config`, `compare --json`.
- Tests covering UDP, TCP, DoT and DoH end to end against an in-process DNS server.
- CI on Python 3.10–3.14, a minimum-dependency job and a Docker build. The image runs as a
  non-root user.

### Changed

- Development status is now *Beta*.
- Minimum `typer` is now 0.13.0 (required by the new `Annotated` / `X | None` CLI signatures), and
  CI checks every declared lower bound with the exact minimum versions.
- `ProbeResult` gains `outcome`, `qname`, `wave` and `ede_codes`. `passed_expectation` is kept
  as a computed field.
- `TargetSummary` rates are `null` when nothing of that kind was tested.
