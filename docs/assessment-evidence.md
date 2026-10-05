# Assessment collection and evidence contract

Phase 2 adds an executable safety/evidence layer, not a full live assessment.
The implemented collector IDs are **`org.settings` and `ghes.meta`**; evaluator IDs
remain **none**. All other 65 catalogue collectors are unimplemented and retain
explicit reasons instead of invented successful probes.

## Explicit scope and live consent

```bash
ghqr assess preflight --live --config /path/customer.yaml
```

The command uses the embedded profile unless `--profile` explicitly overrides it.
Only organizations/instances in config are probed; enterprise-wide discovery and
credential-accessible target discovery are not performed. Without `--live`, no
requests are sent. API credential values are resolved only from the named
per-target environment references. There is no cross-host `GH_TOKEN` fallback.

Cloud and GHES REST routes differ from GraphQL and GHES management routes.
Management uses TLS on port 8443, `/manage/v1/`, and its separate Basic username
and password references, never a PAT routed through `/api/v3`.

Every client shares a run-wide budget of at most four in-flight full-response
requests. REST writes are blocked. GraphQL POST is allowed only for an inspected
read-only query, not mutations/subscriptions. The catalogue's query text is never
executed. GET is not assumed universally side-effect-free: SBOM generation GET
is explicitly prohibited.

Rate handling distinguishes permissions from primary/secondary limits, including
403, 429 and GraphQL HTTP-200 `RATE_LIMITED`/secondary envelopes. Retry/reset hints
are honored with minimum 60-second exponential retry waits and up to five retries.
All waits are injectable in fixtures. Successful queries at zero remaining budget
are not repeated; the next request is paced. Redirects are not followed with
credentials. Pagination follows cursor or numeric next links while retaining the
same host, resource path and filters; a failed page makes the feature incomplete.

## Privacy is a persistence boundary

Secret-scanning schemas return literal `secret` values; they are not safe merely
because they are read APIs. Alert requests add `hide_secret=true`, and every
response is still sanitized regardless of status.

Raw JSON, sidecars, reports and replayed/imported data share the privacy boundary.
It removes literal secrets, their duplicate occurrences in values/property names,
personal email, labeled passwords/tokens, private-key material, LDAP credentials,
and untrusted free-text messages/comments. Webhook destinations retain only their
host, not userinfo, paths or signed/query credentials. Known secrets are retained
only in race-safe memory for later-page/error/log redaction. Base64 UTF-8 content
is inspected rather than treated as opaque. Unsupported binary/non-JSON input
and key collisions caused by redaction fail explicitly.

Safe JSON booleans, nulls, large numeric identifiers, secret type and lifecycle
metadata remain intact. A self-claimed `already_redacted` import flag is ignored.
This is not a claim that arbitrary screenshots/PDFs are automatically safe; their
import contracts are not implemented.

## Raw objects, sidecars and replay

The evidence directory contains sanitized immutable pairs:

```text
objects/{pair-digest}.json
objects/{pair-digest}.meta.json
scopes/{host}/{kind}/{name}/{collector}/{feature}.ref.json
runs/{timestamp}.json
feasibility.json
collection-log.json
```

An atomic logical reference points to the matching complete pair. A failed write
cannot replace the previous pair; repeating the same raw data/provenance is
idempotent. A subsequent run updates the logical reference while preserving old
immutable objects. This intentionally differs from destructively overwriting
raw history. Atomic rename behavior is validated on the local Unix host.

All paths are confined with Go's `os.Root`. Replay checks raw/pair digests, scope,
feature and active profile identity, and sanitizes again; an edited bundle cannot
claim its own safety. Sidecar completeness refers to the raw page. Feature-wide
completeness comes from the final `CollectorOutcome`, not any single page.

```bash
ghqr assess import --config /path/customer.yaml \
  --input /path/payload.json --metadata /path/payload.meta.json
ghqr assess replay --config /path/customer.yaml \
  --host github.com --scope-kind organization --scope example-platform \
  --collector org.secret_scanning_alerts --feature imported-alerts
```

Imports require explicit authorized scope, collection time and matching profile
identity. Their actual provenance is marked `source_kind: import`, regardless of
the claimed source in input metadata. Import/replay commands work outside the
checkout and require no network. Replayed output remains sanitized.

## Validation and API drift

`GOTOOLCHAIN=go1.26.0 make test` passes the fixtures and repository checks.
Fixtures cover 125-record pagination, failed 403/404 pages, permission versus
rate errors, no-real-sleep retries, GraphQL HTTP-200 limits, blocked writes,
management credential separation, 16 requests peaking at four, successful alert
secret/email redaction, duplicate values in comments/keys/later pages/logs,
webhook URL stripping, atomic/idempotent pairs, tampering and scoped imports.
The built import/replay CLI also passes a privacy smoke test outside the checkout.
No live tenant, GHES instance or production performance acceptance was exercised.

Authority references:

- [REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [GraphQL limits](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api)
- [Secret-scanning response schemas](https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28)
- [GHES management API](https://docs.github.com/en/enterprise-server@latest/rest/enterprise-admin/manage-ghes)
- [SBOM endpoint lifecycle](https://docs.github.com/en/rest/dependency-graph/sboms?apiVersion=2022-11-28)

The legacy SBOM GET is documented to sunset after 2026-11-13; the replacement
generation endpoint creates a job despite using GET. Do not invoke it automatically.
Future collectors must use available legacy reads, imported SBOM or an explicitly
supplied already-generated report ID and must never forward GitHub credentials
to signed-download hosts or persist signed URL credentials.

The profile's <=1,000-node GraphQL budget is an offering limit, not GitHub's
500,000-node ceiling. Future nested PR/review collectors must use smaller
pagination batches; `100 PRs * 50 reviews` exceeds the offering budget.
