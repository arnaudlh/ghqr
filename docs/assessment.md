# Evidence-backed Well-Architected assessment

**Status: Phases 1 and 2 are published; Phase 3's inventory/rules/workflows
vertical slice (`ghqr assess run`) is locally verified.**
The exact profile is embedded in the binary, and default offline commands work
outside the checkout. Scoring, interview evaluators and the remaining collector
catalogue are not implemented.
`ghqr assess run` additionally implements `org.repos`, `org.properties`,
`repo.details`, `repo.rules`, `repo.workflows`, `repo.languages` and `repo.sbom`,
for eight implemented collectors in total; the remaining 59 catalogue collectors
and all control evaluators remain unimplemented. Catalogue counts are not
completion counts. This workflow is separate from `ghqr scan`; it does not
reinterpret legacy recommendation descriptors as Well-Architected controls.

## Authority and profile identity

The [GitHub Well-Architected Framework](https://learn.github.com/well-architected)
governs normative intent and contextual tradeoffs. [GitHub Docs](https://docs.github.com)
governs API and platform facts. The supplied automation profile version **2.0**
(generated 2026-09-21) specifies this offering's collection and scoring defaults;
its thresholds are not universal GitHub requirements.

The profile contract preserves 456 local IDs and 67 collectors:

| Family | Controls |
| --- | ---: |
| PRD | 76 |
| COL | 31 |
| SEC | 139 |
| GOV | 87 |
| ARC | 123 |

Automation classifications are Full 150, Partial 109 and Manual 197. Origins are
384 `Framework checklist` statements and 72 `Security deep dive` extensions
(SEC-098..139 and GOV-058..087). A SHA-256 fingerprint identifies the exact imported
bytes; loading the catalogue never executes its natural-language rules or endpoint
descriptors.

The raw pillar name `Application Security`, the profile's per-pillar `stats`,
null interview questions and repeated collector references are preserved.
Statistics are checked against the controls. Dependency lists are deduplicated
without rewriting the supplied profile (GOV-011 repeats `org.rulesets`).

The 2026-10-05 research handoff recorded editorial/annotation variants for
PRD-058, PRD-064, ARC-004 and ARC-015, and additional statements in the current
security checklist. Those findings do not silently add controls or change IDs.
Source references preserve origin and profile identity. Their authority URLs are
entry points, not verified per-statement permalink mappings; the extensions still
require review against specific platform documentation.

## Offline interface

The following commands have been built and exercised with the supplied profile:

```bash
ghqr assess profile
ghqr assess plan --config /path/to/customer.yaml
```

The default profile is the exact versioned JSON embedded at build time, with
SHA-256 `5ba0a050468944bee41f46fa4638318d80269b45abc017244ce601c2aebba997`.
No attachment directory or repository-relative runtime path is needed.
`--profile /path/to/automation-spec.json` explicitly overrides the bundled
profile, using the same validation contract. Invalid overrides return an error;
they never silently fall back to the bundled profile. Customer configuration
remains explicit so an offline plan cannot imply consent to discover targets.

`profile` validates exact local IDs, origins, automation counts and collector
references and prints a JSON catalogue summary. `plan` prints an **offline plan**:
all 67 collectors have availability `not-checked` (two have registered implementations), all metrics
are unavailable with reasons, and applicable controls are `NOT_ASSESSED`.
Neither command resolves credentials, contacts GitHub or produces raw evidence.

`ghqr assess preflight` requires explicit `--live` consent and probes only the two
registered collectors on explicitly configured scope objects; it runs before any
repository has been discovered. `ghqr assess run` also requires explicit `--live`
consent and performs the inventory/rules/workflows vertical slice described below.
An offline plan is not `feasibility.json`, a successful preflight, a collection
run or a scored assessment. `ghqr assess` is the planned
repository-native counterpart of the brief's `waf-collect`; legacy scan, replay
and MCP behavior remains independent.

## Vertical slice collection (`ghqr assess run`)

`ghqr assess run --live --config /path/to/customer.yaml` collects, for every
explicitly configured organization: organization settings (`org.settings`), the
complete repository inventory (`org.repos`, following pagination past 100
repositories) and, for every eligible repository, its authoritative details
(`repo.details`), effective default-branch rules (`repo.rules`), workflow YAML
action references (`repo.workflows`), language bytes (`repo.languages`) and
dependency-graph SBOM availability (`repo.sbom`). It is a separate, narrower
registry (`RunImplementedCollectorIDs`) from preflight's pre-discovery probe
registry, because these repository-level collectors require the organization's
repository inventory to already be known.

Active repositories are non-archived, non-fork repositories pushed within 365
days. When the active population exceeds `repository_cap`, a deterministic
stratified sample by visibility and primary language selects up to the cap,
recording its seed, selected repositories and per-stratum allocation so the
selection can be audited and reproduced. Critical repositories use the
configured custom property (`critical_property`/`critical_values`) when the
organization's property schema confirms it exists; otherwise the run falls back
to the 20 most recently pushed active repositories and explicitly flags that
production-environment evidence is not collected by this phase, rather than
silently treating missing environment data as "not production".

Effective default-branch protection merges GitHub's dedicated effective-rules
endpoint (authoritative for ruleset applicability, but silent on legacy
protection and bypass actors) with the repository's full, paginated ruleset
listing and per-ruleset detail (for bypass actors and ref-name condition
provenance) and legacy branch protection. A 404 on the legacy protection
endpoint for a readable repository is treated as a confirmed absence, per
GitHub's documented contract for that endpoint; a 403 is preserved as unknown
and never collapsed into "unprotected". An active ruleset whose ref-name
conditions do not match the repository's default branch never contributes to
its protection or bypass-actor counts, even when the ruleset itself is active.
Rule-type completeness (`completeness`) and bypass-actor completeness
(`bypass_data_complete`) are tracked separately: the dedicated effective-rules
endpoint can confidently resolve rule types while a specific applicable
ruleset's detail fetch still fails, in which case `bypass_actor_count` is a
known lower bound, not a confirmed count, and is flagged accordingly rather
than silently presented as zero. Pooled coverage (`repos_with_default_branch_
protection_pct`, `repos_fully_protected_pct`, `rule_type_coverage`,
`active_org_rulesets_count`) reports as unavailable, preserving the
confidently known subset's numerator/denominator for audit, whenever any
analyzed repository's effective protection could not be confidently assessed:
an incomplete repository is never silently excluded from the pooled
accounting as if it had not been analyzed at all. `repos_fully_protected_pct`
(GOV-070) requires pull_request (>=1 approval), required_status_checks (>=1
context), non_fast_forward and deletion protection; required signatures are
GOV-072's separate criterion and do not gate GOV-070's count, though signature
presence remains visible via `rule_type_coverage`'s `required_signatures`
entry.

Workflow analysis parses each registered workflow's YAML (`gopkg.in/yaml.v3`;
workflows are never executed) and classifies every step- and job-level `uses:`
reference as local, Docker (a distinct `sha256` digest scheme, never
mispresented as a 40-hex git commit SHA pin), GitHub-owned (`actions/*`,
`github/*`), same-organization or third-party. A reference is "SHA-pinned" only
when its ref is an exact 40-character hexadecimal string; a 39- or 41-character
value, a tag, or a value with trailing characters are all "not pinned", and a
ref containing a GitHub Actions expression is "dynamic" (statically
unknowable). A dynamic reference stays inside its category's applicable
population (denominator) rather than being excluded from it, because excluding
it would shrink the denominator and could present a false, artificially
"clean" 100% coverage when the one remaining reference happens to be pinned;
instead, any dynamic reference in a category marks that whole category's pin
metric explicitly unavailable/uncertain, preserving the computed numerator and
denominator for audit. A zero-reference pin denominator also reports as
unavailable, never as a false 100%. CodeQL operational coverage requires both a
CodeQL-supported language with positive bytes (`repo.languages`) and an active
workflow (not merely a matching file path) containing a `github/codeql-action`
step; dependency-feature coverage uses the SBOM-endpoint-available proxy for
"supported manifest" documented by the `repo.sbom` collector notes. Each
feature keeps its own explicit numerator and denominator so the automation
profile's overloaded `eligible_repos_count` key (shared, ambiguously, between
SEC-001's dependency-scanning eligibility and SEC-004's code-scanning
eligibility) is never silently written under one feature's population.

A run reports measured metrics, raw collector outcomes and completeness; it
does not synthesize a control's `IMPLEMENTED`/`PARTIAL`/`NOT_IMPLEMENTED` state
from file presence, and it does not yet produce full per-control
`ControlResult` records, which remain a later phase's responsibility.

## Customer scope and credential references

The brief's single-host YAML form is supported by the preparatory parser:

```yaml
deployment: ghec
organizations: [example-platform]
repository_cap: 300
lookback_days: 90
concurrency: 4
critical_property: criticality
critical_values: [critical, high, tier-0, tier-1]
production_env_regex: "prod|production|live|release"
thresholds: {}
evidence_dir: ./evidence
```

Cloud defaults to `github.com`; Cloud data residency uses `hostname`. Server
requires `deployment: ghes` and `ghes_host`. Mixed instances require explicit
targets rather than assuming that organizations are shared between instances:

```yaml
targets:
  - host: github.com
    deployment: ghec
    organizations: [example-platform]
    credentials:
      kind: app-installation
      token_env: CLOUD_APP_TOKEN
  - host: github.example.com
    deployment: ghes
    organizations: [example-platform]
    credentials:
      kind: classic-pat
      token_env: SERVER_API_TOKEN
      management_username_env: GHES_MANAGE_USER
      management_password_env: GHES_MANAGE_PASSWORD
```

Only environment variable **names**, never tokens/passwords, belong in config.
No credential resolution or routing is implemented yet. Management Console
references are distinct from API token references; the later collection phase
must use HTTPS port 8443 `/manage/v1` with Basic authentication.

Organization lists must be explicit. The preparatory parser rejects `all`,
conflicting single-host/target fields, duplicate host-qualified scopes, unknown
options, invalid expressions and concurrency above four. Enterprise metadata can
be scoped explicitly without authorizing discovery of every organization.

## Unknowns, applicability and confirmation

Missing evidence is `NOT_ASSESSED`, never false, zero, clean or implemented.
Metrics distinguish known numeric/boolean/text values from unavailable data;
string-list and numeric-dictionary payloads retain their JSON array/object shapes
(including the profile's `friction_flags` and `rule_type_coverage`). A known
metric has exactly one typed payload; unavailable/inapplicable metrics have none.
ratio metrics preserve their numerator, denominator and population. A zero
denominator is unavailable, not zero percent or full coverage. Per-organization
keys include the GitHub host. Collection readiness, runtime availability and
collection completeness have separate types.

`open_alerts_trend_90d_pct` is signed relative change:
`(current_backlog - baseline_backlog) / baseline_backlog * 100`. Reductions are
negative (down to -100), increases can exceed 100, and a zero baseline is
unavailable rather than an invented 0% change. Baseline and current observations
are retained. Its thresholds permit finite values >= -100; ordinary coverage
percentage thresholds remain 0..100. Window consistency and lifecycle collection
are requirements for the later alert collector, not capabilities claimed here.

`N/A` is proposed only for a control's deployment scope excluded by the explicit
targets. It must not be inferred from a 404, which can conceal authorization.
Final collectors must retain per-feature failures and incomplete pagination.

Every Partial/Manual control requires assessor input. PRD-041 additionally
requires confirmation despite its Full label. Proposed states remain distinct
from an assessor decision with a named assessor, time, rationale and evidence.
Flags support multiple simultaneous warnings. The workbook target sheet is
explicitly `Controls`, as specified by the brief; no workbook is edited here.

## Local verification and subsequent phases

The mandatory actual-profile fixture expects the exact supplied file at
`internal/assessment/profile/automation-spec.v2.json`. The imported file is
byte-for-byte identical to the supplied source. Its mandatory integrity and
round-trip test passes; no source check is silently skipped. Synthetic fixtures
also exercise schema, identity/reference rejection, unknown-value semantics,
host separation and offline command behavior.

Local validation:

| Command/check | Result |
| --- | --- |
| `GOTOOLCHAIN=go1.26.0 make build` | Passed; binary at `bin/darwin_arm64/ghqr` |
| `go build ./cmd/ghqr` with an explicit output path | Passed |
| `go test ./internal/assessment ./cmd/ghqr/commands` | Passed |
| `GOTOOLCHAIN=go1.26.0 make test` | Passed: lint, vet, module integrity and all race-enabled tests |
| Actual-profile CLI smoke | Passed: 456 exact IDs, 67 unimplemented/not-checked collectors, 581 unavailable metrics and 307 confirmation requirements |
| Supplied/imported profile byte comparison | Passed |
| Embedded source bytes, duplicates, nulls and confirmation contract | Passed |
| Default profile and plan from outside checkout without `--profile` | Passed |
| `ghqr assess run` synthetic vertical-slice fixtures (>100-repository pagination, >100-ruleset pagination, effective-rules/legacy merge, bypass-actor scoping, workflow SHA-pin classification, end-to-end run) | Passed |
| Pooled-metric regression fixtures (dynamic-ref pin uncertainty, incomplete-repository non-silent-exclusion, GOV-070/GOV-072 signature separation, bypass-vs-rule-type completeness separation, zero-observation active-org-ruleset-count) | Passed |

The local default Go 1.27.1 toolchain caused the pinned Go-1.26-built linter to
panic. Selecting the `go.mod` toolchain for the command fixes this without changing
global settings or the Makefile. Use `GOTOOLCHAIN=go1.26.0 make test` on that host.

The initial local-build request did not publish changes. The user subsequently
authorized publishing only the feature branch to `arnaudlh/ghqr`; origin and
branch inspection confirmed that fork target. Safe collection and
evidence/replay, the contractual export mappers and the inventory/rules/
workflows vertical slice described above are now implemented and locally
verified. Broader collectors and metrics, deterministic typed control
evaluation and interviews, and a production-scale (>=50-repository) fixture
harness distinct from this phase's synthetic unit/integration fixtures remain
for later phases; none of those is implemented or verified yet.

A production performance benchmark requires an explicitly supplied safe target.
Fixture timing cannot establish production acceptance.
