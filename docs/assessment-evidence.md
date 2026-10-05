# Assessment collection and evidence contract

The safety/evidence layer supports the separate `ghqr assess` workflow, not a
complete scored assessment. The Phase 4 adapter follow-up has **50 run-wired
collector IDs**, **16 import-only contracts**, **one preflight-only probe**
(`ghes.meta`). Every catalogue ID has a declared path. A registered ID means that
at least one real feature is wired; it does not mean every endpoint or metric in
that collector's profile descriptor is implemented.

Preflight's live probes remain limited to **`org.settings` and `ghes.meta`**.
Its `implemented_collectors` metadata lists all 51 adapters/probes, while
`probe_collectors` lists only these two probe contracts. Offline plans report
51 `Ready` and 16 `ImportOnly` entries, all with access
`not-checked`; readiness alone never yields a score or an evidence reference.
Probe coverage, adapter readiness, observed permission and collection
completeness are distinct; absence of a preflight probe is not proof of absence
of a collection adapter. No evaluator is included in this published increment.
Full control evaluation and raw-evidence-to-analysis replay remain later
milestones.

| Run-wired group | Exact collector IDs |
| --- | --- |
| Inventory, rules and workflows | `org.settings`, `org.repos`, `org.properties`, `repo.details`, `repo.rules`, `repo.workflows`, `repo.languages`, `repo.sbom` |
| Repository activity and metadata | `repo.prs`, `repo.actions_runs`, `repo.commits`, `repo.secrets_env`, `repo.releases_packages`, `repo.discussions_projects` |
| Security | `org.dependabot_alerts`, `org.code_scanning_alerts`, `org.secret_scanning_alerts`, `org.code_security_configs`, `repo.code_scanning`, `repo.contents_probe` |
| Organization governance | `org.members`, `org.outside_collaborators`, `org.teams`, `org.roles`, `org.pat_governance`, `org.installations`, `org.hooks`, `org.rulesets`, `repo.access`, `org.actions_permissions`, `org.runners`, `org.copilot`, `org.packages`, `org.projects` |
| Enterprise and management | `ent.info`, `ghes.manage_api`, `ent.actions_permissions`, `ent.code_security_configs` |
| Audit and security settings | `ent.audit_log`, `org.audit_log`, `ent.audit_log_streams`, `org.secret_scanning_settings`, `org.bypass_requests`, `org.campaigns` |
| Usage, policies and provisioning | `org.api_insights`, `org.billing`, `ent.billing`, `ent.copilot`, `ent.policies`, `ent.scim_users` |

Enterprise/GHES collectors are gated by explicit target configuration, platform
and credentials; registration is not a claim of successful access. Partial
features include code-scanning analyses/autofix, release-attestation digest
verification and enterprise-wide security-configuration coverage. PRs use a
last-100-merged sample and Actions runs a most-recent-1,000 cap; those metrics
retain sampling caveats. Failed or missing peers cannot silently reduce a
population into a clean percentage.

Audit logs use one paginated date-bounded stream with local action classification
and event-ID deduplication. The authoritative numeric `@timestamp` is read, and
day-granular API results are filtered to the exact requested instants. Web
events are retained for 180 days and Git events for seven days; completing API
pagination does not prove older Git-event coverage. Bypass inventories use the
API's maximum month window and disclose that limitation, not a complete
configured 90-day history. Pattern counts describe explicit overrides only,
never unverified default/enterprise inheritance or operational coverage.
Malformed observations make the relevant typed result and collector outcome
incomplete, retaining observed counts, page references and explicit reasons.

Current billing adapters use documented enhanced-platform usage rather than
inventing unavailable legacy Actions-minutes/Packages/shared-storage fields.
API Insights provides organization summaries/time/subject statistics, not every
per-user or per-actor drill-down. Copilot telemetry is window-limited and is not
proof of every user's real activity. Enterprise policies preserve literal
`NO_POLICY` rather than coercing it to false. Missing totals/amounts and malformed
records remain unknown or incomplete with explicit outcome reasons.

Import-only UI/external interiors and the partial features above remain distinct
from complete normalized collectors. Catalogue-ID coverage does not establish
coverage of all profile metrics, evaluator rules or live tenant permissions.

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

SCIM is opt-in through `scim_mode`, independently for each target:

| Mode | Platform/scope | Read-only endpoint |
| --- | --- | --- |
| `emu` | Cloud, explicit enterprise slug | `/scim/v2/enterprises/{enterprise}/Users` |
| `saml_sso` | Cloud, explicitly configured organizations | `/scim/v2/organizations/{org}/Users` |
| `ghes` | Server, appliance-wide; no enterprise slug required | `/api/v3/scim/v2/Users` |

An empty mode is not run; SAML presence never implies EMU. SCIM requires an
explicit classic-PAT credential route, not a fine-grained PAT, App token or
global credential fallback. Required scopes differ by platform and actor
(`scim:enterprise` for setup/GHES; Cloud enterprise-owner read access can use
`admin:enterprise`). An organization-only SAML target or GHES appliance does not
need a fabricated enterprise slug. Index/count pagination validates the server's
actual page sizes/totals and preserves omitted totals separately from zero.

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
This is not a claim that arbitrary screenshots/PDFs are automatically safe:
binary images/documents are not accepted by JSON import. UI settings can be
imported as explicit JSON transcriptions, and documents as reviewed references,
under the contracts below.

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

### Recognized import contracts

For these 16 IDs, the actual `assess import` entry point validates the payload
**before opening the evidence store or writing any evidence**. An invalid
envelope returns an error and no success-shaped reference. Ordinary authorized
API-collector JSON imports retain their existing behavior.

| Family | Collector IDs | Envelope |
| --- | --- | --- |
| Customer-run GHES observations | `ghes.cli`, `ghes.backup` | Typed command/backup observations and `captured_at`; replication status is `OK`, `WARN` or `ERR`, backup status is `success`, `failed` or `unknown` |
| UI transcriptions | `ui.ent_policies`, `ui.ent_auth`, `ui.ent_audit_settings`, `ui.org_pat_policy`, `ui.org_third_party`, `ui.org_code_security_settings`, `ui.org_copilot_policies`, `ui.org_security_overview`, `ui.org_actions_settings` | Matching `collector_id`, `captured_by`, `captured_at`, non-empty `fields` map |
| External observations | `ext.github_status`, `ext.ghes_releases`, `ext.siem_rules` | `source`, `retrieved_at`, non-empty `payload` map |
| Interviews | `manual.interview` | `control_id`, `assessor`, `answered_at`, `response`; optional question and evidence references |
| Reviewed document references | `manual.document` | `control_id`, `document_title`, `reviewed_by`, `reviewed_at`; optional URL and summary |

UI `fields` and external `payload` interiors remain generic maps: the envelope
validator does not establish setting names/types, feature completeness,
operational coverage or a control's scored state. `ImportOnly` is not a live
collector or evaluator. A successful import proves authorized, sanitized
storage and imported provenance, not that the supplied observations are true.

For example, a UI payload accepted for metadata whose collector is
`ui.org_security_overview` is:

```json
{
  "collector_id": "ui.org_security_overview",
  "captured_by": "assessor-reference",
  "captured_at": "2026-10-05T00:00:00Z",
  "fields": {
    "two_factor_required": true
  }
}
```

Use a non-sensitive assessor reference. Matching metadata still needs the active
profile version/SHA, authorized host-qualified scope, collection time and
feature identity. `{"unexpected": true}` is rejected for this collector, rather
than persisted as a valid UI capture. See
[`import_contracts.go`](../internal/assessment/import_contracts.go) for the exact
current shapes and validation constraints.

### Integrity is not derived-analysis verification

Object replay validates the stored sanitized JSON/metadata pair and its
provenance. It does **not** prove arbitrary supplied metrics, effective rules,
critical populations or per-repository analysis. A genuine page unrelated to a
claimed analysis, or a workflow-only check, cannot establish that the complete
report was re-derived. Full offline evaluation must use the same analysis
pipeline against the required raw pages, retaining denied/incomplete outcomes
and unknown observations; this acceptance remains open in the current
increment.

## Validation and API drift

`GOTOOLCHAIN=go1.26.0 make test` passes the fixtures and repository checks.
Fixtures cover 125-record pagination, failed 403/404 pages, permission versus
rate errors, no-real-sleep retries, GraphQL HTTP-200 limits, blocked writes,
management credential separation, 16 requests peaking at four, successful alert
secret/email redaction, duplicate values in comments/keys/later pages/logs,
webhook URL stripping, atomic/idempotent pairs, tampering and scoped imports.
The built import/replay CLI also passes a privacy smoke test outside the checkout.
Permanent core and CLI tests exercise the recognized-import entry point:
invalid payloads create no evidence files, while valid payloads load back with
`source_kind: import`, matching references and sanitized sensitive fields.
The published Phase 4 tree also passes build, vet and the full race suite without
uncommitted evaluator files. Legacy offline mock/replay preserves 55 synthetic
repositories and JSON/Markdown/Excel output; that is legacy compatibility, not
full WAF replay or a production benchmark.
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
