# Evidence-backed Well-Architected assessment

**Status: Phases 1 and 2 are published; Phase 3's inventory/rules/workflows
vertical slice (`ghqr assess run`) is locally verified. Phase 5/6 adds a
typed, deterministic control-evaluation registry, explicit assessor
confirmation and a fully offline `ghqr assess evaluate`/`ghqr assess confirm`
export pipeline, both locally verified.**
The exact profile is embedded in the binary, and default offline commands work
outside the checkout. The remaining collector catalogue and the overwhelming
majority of the profile's 456 controls' automatic rules are not implemented.
`ghqr assess run` additionally implements collectors documented separately in
this file's vertical-slice section; catalogue counts are not completion
counts. This workflow is separate from `ghqr scan`; it does not reinterpret
legacy recommendation descriptors as Well-Architected controls.

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

## Deterministic typed evaluation (`ghqr assess evaluate` / `ghqr assess confirm`)

`ghqr assess evaluate --run <run.json> --config <customer.yaml> --out <dir>` is
fully offline: it never contacts GitHub. It reads an already-collected
`VerticalSliceReport` (a prior `ghqr assess run --live` run.json, or any
equivalent fixture in the same JSON shape), proposes one result per profile
control via an explicit, approved typed registry/dispatch keyed by control ID
(never natural-language parsing of `Control.Rule`, never AI scoring), and
writes every contractual export artifact to `--out`:
`feasibility.json`, `metrics.json` (581 declared metric keys), `results.csv`
(456 exact IDs, 10 columns), `interview-guide.md` (307 required-confirmation
entries), `collection-log.json`, `summary.md`, `workbook-update.csv` (259
non-Manual rows) and this package's own `evaluation-results.json` round-trip
artifact. `ghqr assess confirm --decisions <file> --out <dir>` loads that
round-trip artifact, applies explicit assessor decisions, and re-renders the
result-derived exports in place; it never re-runs a typed evaluator and never
re-derives `feasibility.json`/`metrics.json`/`collection-log.json`, which
depend only on the original collected run.

**Exact implemented evaluator coverage as of this handoff: fifteen control IDs** —
`ARC-005`, `ARC-093`, `ARC-104`, `COL-001`, `COL-027`, `GOV-001`, `GOV-065`,
`GOV-070`, `GOV-072`, `PRD-016`, `PRD-029`, `SEC-016`, `SEC-043`, `SEC-099`,
`SEC-132` (`assessment.ImplementedEvaluatorIDs()`).
**This registry is explicitly open, not a completed phase**: it is a small,
genuine subset of the profile's 150 Full-automation controls (244 of the 259
Full+Partial controls still have no typed evaluator), not an approximation of
full coverage, and it must never be inferred from the 456-row shape of
`results.csv`: every row exists because the export contract requires exactly
one result per profile control, not because 456 controls were genuinely
scored. The remaining 441 controls are `NOT_ASSESSED` with a reason generated
per control, never a single generic placeholder: a Manual control states that
the profile defines no automatic rule for it; a Full/Partial control without
a registered evaluator names, by this run's actual per-metric `MetricStatus`
(never mere map-key presence), which of its declared metrics this run
genuinely measured (`known`), which it computed but came back inconclusive,
and which it never attempted at all. A control's proposed *state* being
`NOT_ASSESSED` never blanks out a metric this run genuinely measured for that
same control — data and score are tracked separately, and `metrics.json`
reuses a control's one unambiguous genuinely-known observation for a shared
metric key even when no control that references it has a registered
evaluator yet.

Each evaluator implements the exact profile rule text for a control whose
declared metric key(s) match a signal this run's vertical slice genuinely
computes, with inclusive-upper/inclusive-lower tier boundaries (a value
exactly on a threshold counts for the higher tier that threshold defines):
`ARC-005` and `GOV-001` gate on `repos_with_default_branch_protection_pct`
alone; `COL-027` gates on `team_based_access_pct` alone; `GOV-070` gates on
`repos_fully_protected_pct` (this run's documented GOV-070 definition);
`GOV-072` gates on a newly derived `critical_repos_requiring_signatures_pct`
(required_signatures presence scoped to each organization's confirmed
critical population, excluded entirely from the pooled accounting when that
population itself could not be confirmed); `SEC-043` gates on
`dependabot_security_updates_pct` (explicitly disclosing that it substitutes
the repo.sbom/repo.details-derived signal for the profile's cited
repo.contents_probe/org.code_security_configs collectors, under the same
declared metric key); `SEC-099` gates on `third_party_refs_sha_pinned_pct`
and separately reports (never gates on) `github_owned_refs_sha_pinned_pct`.
`GOV-001` and `COL-027` are Partial automation and therefore always require
assessor confirmation regardless of their proposed tier; each evaluator's
interview half (whether teams can explain ruleset intent / map to real
delivery teams) is never assumed satisfied.

For the four compound rules (`GOV-070`, `GOV-072`, `SEC-043`, `SEC-099`), each
rule's secondary AND-condition metric (`org_default_branch_rulesets_active`,
`verified_commit_ratio_pct`, `repos_with_grouped_version_updates_pct`,
`repos_with_actions_ecosystem_updates_pct` respectively) is now genuinely
computed by this run's collectors and is consulted whenever the primary gate
alone reaches the IMPLEMENTED floor: a confirmed-passing secondary (against
its own literal threshold from the rule text — never an invented number)
confirms IMPLEMENTED. For `GOV-070`, `SEC-043` and `SEC-099`, a
confirmed-*failing* secondary does **not** invent a PARTIAL downgrade: each
of these three rules' literal PART/NOT text conditions those tiers purely on
the primary gate and never mentions the secondary at all, so a top-range gate
combined with a known-failing secondary is a combination with no mapping in
the rule's literal text at all and is reported `NOT_ASSESSED` with an
explicit "ambiguous/unmapped rule combination" disclosure, exactly like an
unmeasured secondary — the two cases differ only in their Notes wording
("secondary not computed" vs. "secondary confirmed failing, no textual
mapping exists"), never in the proposed state. `GOV-072` is the sole genuine
exception, because its own literal PART clause is an explicit OR of two
independent sub-bands ("rule present 50-95% OR verified ratio 80-95%"): a
dedicated `govSeventyTwoCompoundTier` two-variable matrix confirms IMPLEMENTED
only when both metrics independently reach their own floor, confirms PARTIAL
whenever *either* metric's own tier lands in its own literal PART band (not a
shared floor), falls to NOT_IMPLEMENTED only when the primary itself is below
its own 50% floor, and reports the one remaining textually-unmapped cell
(primary at/above its implemented floor, secondary known but below its own
80% PART floor) as the same explicit `NOT_ASSESSED`/ambiguous disclosure. The
PARTIAL/NOT_IMPLEMENTED tiers for `GOV-070`/`SEC-043`/`SEC-099`, whose rule
text conditions them only on the primary gate metric, resolve directly in
every case and never require the secondary signal.

**Round 11 added four more genuinely implemented control IDs** by
systematically cross-referencing every remaining Full/Partial control's own
declared metric keys against the exact metric keys this run's collectors
genuinely populate, never the profile's conceptual metric *names* alone.
`ARC-093` and `ARC-104` declare identical rule text verbatim ("IMPL if
owners <= 5 (or <= 5% of members), team-based access >= 90%, and roles used
beyond owner/member (security_manager/custom); PART if one criterion fails;
NOT if two or more"), implemented as a shared literal 3-criteria pass/fail
count exactly mirroring `SEC-016`'s own established pattern: the owner
cap-or-ratio clause is evaluated per organization (never pooled, the same
fix applied to `SEC-016` in an earlier round, this time built in from the
start) via a dedicated helper distinct from `SEC-016`'s own owner formula
(ARC-093/104's literal clause is a plain OR between the absolute and ratio
caps; `SEC-016`'s is a stricter AND with its own `<=2` escape hatch — the two
controls' textual formulas genuinely differ and must never share one
implementation). "Roles used beyond owner/member" is read as the rule's own
named examples (`security_manager_teams`/`custom_roles_count`), and the
control's own declared `roles_in_use` metric is derived as their sum (or
either alone with a disclosed lower-bound caveat when only one resolved).
`SEC-132` and `GOV-065` are each capped at PARTIAL even when their one
independently-measurable signal (`security_manager_teams` presence;
`outside_collab_ratio_pct` below its 5% floor, respectively) fully supports
it: both controls' own literal IMPLEMENTED clause has a second, genuinely
unverifiable AND-condition this run's collected data cannot answer (whether
any security-team member holds owner *solely for security work*; a
customer-maintained justification register and quarterly-evidenced access
reviews), mirroring `PRD-029`'s established "never proposes IMPLEMENTED
from data alone" pattern rather than inventing a confirmation this run never
received. `GOV-065`'s own literal ratio thresholds (5%/10%) still determine
the PARTIAL-vs-NOT_IMPLEMENTED boundary exactly as written — a ratio above
10% remains a genuine NOT_IMPLEMENTED regardless of the separately-unverifiable
clauses. Two further candidates with the same owner/role signals available
(`GOV-017`, `SEC-017`) were explicitly identified but deferred: their own
literal text combines an owners-count PART/NOT band stated purely in
absolute-count terms ("owners 6-10") with a separate IMPLEMENTED-only escape
via the ratio ("or <= 5% of members"), and it is not evident from the text
alone whether the ratio escape is meant to also widen the PART/NOT band
boundaries themselves — implementing either reading risked inventing a
threshold interaction the rule's own text does not unambiguously state, so
both remain `NOT_ASSESSED` pending a clearer literal resolution rather than
a guessed interpretation.

A customer-accepted threshold override (`config.Thresholds[metricKey]`,
parsed from the customer configuration) replaces a control's IMPLEMENTED
(upper) floor only; the PARTIAL (lower) floor always stays at the profile
default. Every evaluator honors an override when present: the proposed tier,
the confidence distance-from-floor calculation, and the rendered Notes text
(an explicit "(customer-accepted threshold override: implemented floor is
X%, not the profile default Y%)" disclosure) are all computed against the
resolved floor, never the stale profile default — an accepted override is
never silently ignored, and its applied value is never hidden from the
exported Notes.

`GOV-070` additionally implements the rule's "or missing one rule type"
PARTIAL-widening clause: when the plain `repos_fully_protected_pct` tier
would be NOT_IMPLEMENTED, a self-computed per-rule-type coverage pool (over
the same confidently-assessed repository population, `pull_request`,
`required_status_checks`, `non_fast_forward` and `deletion` only —
`required_signatures` is GOV-072's separate criterion and is never folded in
here) widens that tier to PARTIAL only when the math assigns exactly one of
those four types as having zero coverage across every confidently-assessed
repository; zero, two, three or four such types, or no confidently-assessed
population at all, leave the plain percentage tier unchanged, with the reason
explicitly disclosed either way (never silently applied or silently skipped).
For a multi-organization run, `GOV-070`'s pooled
`org_default_branch_rulesets_active` boolean secondary is never confirmed
from a simple cross-organization OR: a single small, compliant organization
must never be allowed to mask a larger, non-compliant one, so confirmation
requires every analyzed organization's own per-organization value to
independently agree (falling back to the single `Overall` value only when a
run has no per-organization breakdown at all, i.e. exactly one organization).

Four further evaluators, registered once the corrected collector work landed
their exact declared metric keys: `COL-001` (Partial; `review_coverage_pct`
gates PART/NOT directly, `median_time_to_first_review_h` independently
contributes an OR'd PARTIAL via its own `<=8h`/`<=24h` bands, the
design-discussion interview half always deferred to mandatory
confirmation — reusing the same `orMatrixTier` shared helper `GOV-072`
introduced, generalized for a lower-is-better secondary); `PRD-016` (Partial;
`ci_success_rate_90d` gates PART/NOT directly, `median_queue_time_min`'s
single `<=2min` requirement gates IMPLEMENTED via `gatedTier`'s existing
single-floor pattern through a floor-negation convention, the "reviewed at
least monthly" interview half deferred at every tier, not only the top one);
`PRD-029` (Full; `hooks_without_secret_pct`'s literal 0%/0-30%/>30% bands gate
the tier, `hooks_insecure_ssl_count==0` required in addition for
IMPLEMENTED — this control's "GitHub Apps vs classic PAT dominance" nuance
has no declared classic-PAT-count metric to compare against and is
explicitly disclosed as unverified in every proposal's Notes, never silently
assumed); `SEC-016` (Full; a literal 5-criteria pass/fail count —
`default_repository_permission`, the owner count/ratio escape-hatch pair,
`repos_with_direct_collaborators_pct`, `outside_collab_ratio_pct`,
`members_without_2fa` — IMPLEMENTED requires 0 failures, PARTIAL exactly 1,
NOT_IMPLEMENTED 2 or more, confidence deliberately capped at Medium since no
single percentage-floor "distance from boundary" concept generalizes across
5 heterogeneous criteria).

**Controls explicitly considered and deferred, not silently skipped:** a
re-scan against the full expanded metric set (including the second
collector-development round's new exact-named keys) found several further
controls with only one or two missing metrics
(`SEC-017`, `SEC-067`, `GOV-017`, `ARC-038`, `ARC-093`, `ARC-098`,
`ARC-104`, `ARC-109`, `SEC-002`, `SEC-010`, `SEC-082`, `SEC-132`, `GOV-036`,
`GOV-060`). None were added to the registry: several (`SEC-017`, `GOV-017`,
`ARC-093`, `ARC-104`, `SEC-082`, `GOV-060`) have rule text where the *missing*
metric can independently force NOT_IMPLEMENTED even when the measured gate
looks high (for example "NOT if ... security staff are owners" or "NOT if
requirement disabled"), which breaks this registry's established assumption
that PART/NOT_IMPLEMENTED resolve from the gate alone — silently applying the
existing gated pattern to these would risk mis-tiering a control that is
actually NOT_IMPLEMENTED as PARTIAL or better. Others (`ARC-038`,
`ARC-098`, `ARC-109`) have genuinely ambiguous compound thresholds (an
unnormalized count against no stated denominator, or a shared percentage
band applied across two different variables without a clear single-gate
reading). The rest (`SEC-067`, `SEC-002`, `SEC-010`, `SEC-132`, `GOV-036`)
either have no numeric gate in their tier definitions at all (purely
document/interview-determined) or require 2-of-3 unmeasured signals.
Implementing any of these would require inventing an interpretation the rule
text does not clearly support, which this registry's design explicitly
refuses to do. (`PRD-029`, previously on this deferred list, was later
re-examined and found to have one crisply numeric, defensible sub-rule —
its webhook-secret/SSL half — that could be typed honestly while explicitly
disclosing the remaining "classic PAT dominance" nuance as unverified; see
above.)

**Source provenance for `--run`:** `ghqr assess evaluate`'s optional
`--evidence-dir` flag verifies, page by page, that every collector outcome
the supplied run report cites actually resolves to a real, digest-identity-
verified object in that evidence store (`VerifyReportEvidence`, reusing
`EvidenceStore.LoadJSON`'s existing identity/digest contract) before
evaluation proceeds; evaluation is refused outright, with no export files
written, when any cited evidence does not genuinely resolve there. This
defends against a hand-edited or fabricated run report claiming scores no
real collection ever produced — a forged report's invented outcomes will not
resolve against a genuine evidence store, because resolution requires the
exact scope/collector/feature identity and content digest recorded at
collection time, not merely a matching file path. A report that claims
genuinely computed analysis (any repository's effective protection or
workflow analysis, or any pooled metric reported known) while citing zero
outcomes, or while zero of its cited pages actually resolve, is explicitly
refused rather than accepted as "verified" on a vacuous, zero-evidence pass;
a genuinely empty, unanalyzed report is not penalized for having nothing to
verify.

Resolving a cited page's digest/identity proves it was genuinely persisted;
it does not, by itself, prove the report's *derived* facts still match that
raw evidence (an evidence ref can be entirely genuine while the claimed
analysis built from it was independently altered, or a page's actual content
is simply unrelated to what it claims to support — digest/identity checks
alone cannot detect either). `--evidence-dir` closes this gap with genuine
raw-evidence *replay*: for every analyzed repository the report claims a
fact for, its effective default-branch protection and workflow
action-reference analysis are re-derived directly from `evidenceDirectory`
by calling the exact same exported collection/analysis pipeline a live run
uses — `ComputeEffectiveBranchProtection` and `AnalyzeRepositoryWorkflows` —
through a replay-mode `CollectionClient` that serves only already-persisted
pages and never makes a network call (`newReplayCollectionClient`, an
additive `CollectionClient.replaySource` field with an early-return branch
in `CollectGET`/`CollectGraphQL`; imported-vs-collected provenance and each
page's original HTTP status/completeness survive the replay unchanged). The
re-derived result is compared against the report's claim
(`compareEffectiveProtection`/`compareWorkflowAnalysis`): a mismatch on any
gated protection field, a claimed completeness exceeding what the genuinely
persisted pages can independently prove (a missing required page, such as a
never-collected legacy-protection response, caps what replay can confirm
even when every *other* page is genuine), or a workflow reference list/
classification that doesn't match the stored content, each fails
verification with an explicit, repository-identified reason. A repository
the report makes no claim for at all is skipped; one it does claim a fact
for, with no evidence to replay against, is not skipped — replay runs
anyway, genuinely proves nothing, and that absence is compared like any
other result, so an unbound claim with missing required pages is rejected,
never silently waived. This is still a bounded replay: it genuinely re-runs
the real multi-ruleset/legacy-protection merge (`ComputeEffectiveBranchProtection`
itself, unmodified), but does not independently re-derive which repositories
belong to each organization's confirmed critical population (that
determination's own collector is not replayed; GOV-072 still reuses the
report's claimed critical-population membership as-is) — an explicit,
documented limitation. It reuses the collecting run's own exported functions
verbatim — no duplicated merge or parsing logic — for every fact family it
does cover. Omitting `--evidence-dir` skips all of the above and trusts the
supplied run report at face value, which remains the intended path for
synthetic fixtures and this package's own test suite.

Confidence is deterministic, not a model's self-reported certainty: high only
when every repository contributing to the gate metric was confidently
(non-partially) assessed, the organization's active population was not
reduced by sampling, and the measured value sits more than 10 percentage
points from both tier boundaries; medium for an otherwise-complete measurement
within 10 points of a boundary; low whenever any contributing collection was
sampled or incomplete. The `verify-endpoint` result flag is emitted only when
an evaluator actually used a collector the loaded profile marks
`verify: true`; none of the fifteen currently registered evaluators' collectors
carry that flag, so it is exercised by a dedicated unit test rather than by
any of the fifteen today. Pooled metrics sum numerators/denominators (never
average per-organization percentages); each evaluator also derives its own
per-organization breakdown directly from the run's per-repository records
(`VerticalSliceReport.Organizations[].Repositories[]`), independently of
`vertical_slice_metrics.go`'s pooled-overall-only accumulator, so organization-
scoped observations and evidence references are genuinely computed, not
copied from the pooled total.

`metrics.json`'s 581-key catalogue never resolves a metric key shared across
multiple controls by iteration order ("last write wins"): a key with no known
observation anywhere keeps the offline-plan's unavailable baseline; a key
with exactly one genuine known source (including the same signal reused
byte-for-byte across several controls, such as `repos_with_default_branch_
protection_pct` between `ARC-005` and `GOV-001`) carries that source; a key
where two controls computed two genuinely *different* known observations
(the profile reuses some metric names, such as `eligible_repos_count`, across
controls with different feature-specific populations) is reported explicitly
ambiguous, naming both conflicting control IDs, rather than silently picking
one control's context and presenting it as if it applied to the other.

Assessor confirmation is a separate, explicit input: `AssessorInput`
(`control_id`/`state`/`assessor`/`confirmed_at`/`rationale`/`evidence_refs`)
is read from an external JSON array via `--decisions`, never synthesized from
a proposed state, a rule's text or an interview question. Validation rejects
an unknown control ID or state, an empty assessor identity or rationale, a
zero or future-dated confirmation timestamp (a future date cannot be a
genuine confirmation and is rejected as a fake permission grant, not clamped
or silently accepted) and a decision with no evidence reference at all; one
invalid decision fails the whole batch rather than partially applying it.
Applying a decision only ever sets a result's separate `Decision` field; it
never mutates the proposal's `ProposedState`/`Confidence`/`Flags`/`Metrics`/
`EvidenceRefs`/`Notes`, preserving the contract that a proposal and its
confirmation are always distinguishable. `PendingConfirmations` reports every
control still awaiting confirmation; nothing in this package finalizes a
Manual, Partial or PRD-041 control on the caller's behalf, and no RAI/
automated explanation or unconfirmed interview answer ever rates an unobserved
control. Export artifacts pass through the same privacy boundary as every
other persisted output: JSON artifacts go through `EvidenceStore.WriteReport`'s
structural JSON redaction, while the CSV/Markdown artifacts go through the
plain-text `Redactor.Text` boundary before the same atomic, root-bounded write
(running the JSON redactor over non-JSON CSV/Markdown would reject it as
invalid JSON rather than sanitizing it). One practical consequence: an
assessor identity supplied in email form is redacted to `[REDACTED_EMAIL]` in
every exported artifact, the same as any other literal email the pipeline
encounters.


## Local verification and subsequent phases

The mandatory actual-profile fixture expects the exact supplied file at
`internal/assessment/profile/automation-spec.v2.json`. The imported file is
byte-for-byte identical to the supplied source. Its mandatory integrity and
round-trip test passes; no source check is silently skipped. Synthetic fixtures
also exercise schema, identity/reference rejection, unknown-value semantics,
host separation and offline command behavior.

### Full-pipeline evidence replay (superseding the earlier workflow-only/narrow-helper approach)

An earlier round's replay implementation re-derived only effective
default-branch protection and workflow action-reference analysis through two
exported helpers, trusting a claimed report's organization/critical-
population/feature/metric facts for everything else. This was judged
insufficient: a genuine, digest-verified evidence page for one collector
(e.g. `repo.rules`) does not, by itself, prove any OTHER claimed fact about
the same run. `ReplayVerticalSlice` (`internal/assessment/evidence_replay.go`)
now calls the exact same `runVerticalSliceWithStore` pipeline a live
`ghqr assess run` uses, through a replay-mode client factory
(`NewReplayCollectionClient`) that serves only already-persisted pages and
never dials a network: every organization, population, critical-population
determination, repository, feature signal, pooled/per-organization metric
and target-level (enterprise/instance) operational result (compared via a
full struct equality check, not a hand-picked field subset, so a newly added
field such as a future CodeQL signal is covered automatically) is
independently reconstructed, not trusted from the claim. `VerifyReportEvidence`
now reports `IntegrityVerified` (every cited evidence page genuinely
resolves and its digest matches) and `AnalysisVerified` (the claim's derived
facts match what replay independently reconstructs) as distinct fields;
`Verified` is their conjunction. `RunVerifiedOfflineEvaluation` evaluates
using the *replayed* report after successful verification, never the
originally supplied one.

**`RunCollectionContext`** (`internal/assessment/run_collection_context.go`)
closes a gap a later review round caught in the first version of this
mechanism: binding non-secret configuration provenance (deployment,
enterprise, credential kind, SCIM mode, repository cap, lookback, critical
property/values, production-environment regex) by INFERRING it from the
claimed report's own hostname pattern and `CollectorOutcome` entries was
itself still a form of trusting the claim (and silently defaulted
non-default lookback/critical-property/values/production-regex settings a
real customer's config might genuinely have set). `WriteRunCollectionContext`
is now called once, immediately after a live `RunVerticalSlice` call succeeds
(wired into the `ghqr assess run` CLI command), and persists an immutable,
write-once record of the EXACT `*CustomerConfig`/resolved `[]Target` that
run was actually validated and authorized against -- excluding every
credential *value* (never a token, username or password, only
`CredentialKind`) and reading no global/environment state at replay time.
`ReplayVerticalSlice` reads this record directly (`LoadRunCollectionContext`)
and binds its own `Targets`/`CustomerConfig` reconstruction to it exactly,
with zero inference, for every evidence directory produced by this round's
code. A legacy bundle collected before this mechanism existed (or produced
by a different tool) falls back to the prior inference-based reconstruction,
but `EvidenceVerificationResult.ContextBound` reports `false` for it, and
`AnalysisVerified` is never a blanket `true` for a legacy bundle regardless
of how cleanly its inferred-settings comparison happens to come out -- an
explicit, disclosed compatibility limitation, not silent equivalence with a
genuinely context-bound run. SCIM routing mode (`emu`/`saml_sso`/`ghes`) is
now captured and bound through this same context (previously an explicit,
disclosed gap: no `CollectorOutcome` field recorded it at all).

The live-client (`NewCollectionClient`) and replay-client
(`NewReplayCollectionClient`) constructors share one platform-routing
helper (`resolveCollectionEndpointAddress`) for REST/GraphQL/management-console
base-URL construction, so the two can never independently drift into
duplicated, separately-maintained copies of the same host-routing formula.

Three real issues surfaced and were fixed while building this across two
review rounds: (1) the parent's own 5th overlay gate reproduced that a
genuine-but-unrelated evidence page for one collector let an unrelated
claimed derived fact verify as `true` (fixed by full-pipeline reconstruction
instead of per-collector page-resolution alone); (2) replaying with
`Concurrency:4` (matching a live run's own default) reproduced an
intermittent (~1-in-3 runs under `go test -race`) permanent hang: a
goroutine dump during one such hang showed a stuck raw syscall inside
`os.(*Root).Rename`, occurring specifically under replay's dual
evidence-store access pattern (concurrent reads from the source store,
concurrent writes to a scratch store, both `os.Root`-backed, from multiple
goroutines at once); `replayConcurrency` now pins replay to `1` -- a
bounded, empirically confirmed fix for this one observed, reproducible
failure mode in this specific usage pattern (stable across 10+ repeated
full-pipeline runs with comparable wall-clock cost), not a general claim
that concurrent `os.Root` access is inherently unsafe in Go, which was not
independently root-caused or isolated from this package's own dual-store
pattern; (3) forcing every replay client to `NoCredential` and inferring
Deployment/enterprise/credential-kind from the claim's own hostname and
Outcomes (rather than genuine bound provenance) made credential- and
deployment-sensitive collectors such as `FetchEnterpriseSCIMUsers` either
unreachable during replay or validated against invented settings; fixed by
`RunCollectionContext`.

### Local verification

| Command/check | Result |
| --- | --- |
| `GOTOOLCHAIN=go1.26.0 make build` | Passed; binary at `bin/darwin_arm64/ghqr` |
| `go build ./cmd/ghqr` with an explicit output path | Passed |
| `go test ./internal/assessment ./cmd/ghqr/commands` | Passed |
| `GOTOOLCHAIN=go1.26.0 make test` | Passed through Round 8: lint, vet, module integrity and all race-enabled tests. Round 9: lint/vet/the full race suite/`make build` independently confirmed green by running their exact underlying commands directly; `make test`'s own `tidy` sub-target (`go mod tidy` + `git diff --exit-code ./go.mod`/`./go.sum`) cannot itself report clean this round because Phase4's attestation work now depends on `github.com/sigstore/sigstore-go` (a legitimate new external dependency never yet committed to git in this session) while this session's own explicit constraint is no git commits from either agent -- this is a structural gap requiring an actual commit outside either agent's authority, not a code defect or flakiness |
| Actual-profile CLI smoke | Passed: 456 exact IDs, 67 unimplemented/not-checked collectors, 581 unavailable metrics and 307 confirmation requirements |
| Supplied/imported profile byte comparison | Passed |
| Embedded source bytes, duplicates, nulls and confirmation contract | Passed |
| Default profile and plan from outside checkout without `--profile` | Passed |
| `ghqr assess run` synthetic vertical-slice fixtures (>100-repository pagination, >100-ruleset pagination, effective-rules/legacy merge, bypass-actor scoping, workflow SHA-pin classification, end-to-end run) | Passed |
| Pooled-metric regression fixtures (dynamic-ref pin uncertainty, incomplete-repository non-silent-exclusion, GOV-070/GOV-072 signature separation, bypass-vs-rule-type completeness separation, zero-observation active-org-ruleset-count) | Passed |
| Typed evaluator boundary/compound/gate fixtures (ARC-005/GOV-001/GOV-070/GOV-072/SEC-043/SEC-099 inclusive-tier boundaries, compound-rule NOT_ASSESSED-at-top-tier gating, zero/incomplete-population unavailability, deterministic confidence, verify-endpoint flag) | Passed |
| Assessor confirmation contract fixtures (unknown ID/state/empty rationale/zero and future timestamps/no evidence rejection, batch-atomicity, proposal immutability) | Passed |
| Export-pipeline contract fixtures (`metrics.json` known-vs-unknown merge order independence, ambiguous shared-metric-key conflict detection, unimplemented-control data-vs-score preservation, full offline `ghqr assess evaluate`/`ghqr assess confirm` round trip writing/re-rendering all 8 files) | Passed |
| GOV-070 missing-one-rule-type widening fixtures (exactly-one-type-zero-coverage widens NOT_IMPLEMENTED to PARTIAL; zero/two/four-type and zero-population cases correctly do not widen, each explicitly disclosed) | Passed |
| Full-pipeline replay fixtures (a true, real, >=50-active-repository (stratified-sampled to 55) raw collection against a synthetic fixture organization, independently reconstructed end to end through `ReplayVerticalSlice`/`runVerticalSliceWithStore`, not a narrowed per-repo helper; genuine-claim match confirmed with zero mismatches; tampered-claim detection for an added workflow reference, a reclassified pin-status, a changed critical-population membership, a changed reported FullName/DefaultBranch, and an altered pooled metric value, all compared against one shared replay result; true end-to-end `RunVerifiedOfflineEvaluation` acceptance proven separately against a smaller dedicated fixture) | Passed |
| Direct comparison-function unit fixtures (`compareEffectiveProtection`/`compareWorkflowAnalysis` tampered-field/reclassified-reference/missing-page-completeness detection, pipeline-free) | Passed |
| `RunCollectionContext` binding fixtures: a genuine, nondefault configuration (custom repository cap/lookback/critical property+values/production-env regex) is captured verbatim and bound by replay, not defaulted or inferred; an evidence directory with its `run-context.json` altered on disk to claim a different, never-collected organization is rejected (hard replay failure or explicit comparison mismatch); a legacy bundle with no written context reports `ContextBound=false` and never earns a blanket `AnalysisVerified=true`, even when its underlying best-effort comparison is otherwise clean; SCIM routing mode (`emu`/`saml_sso`/`ghes`) and credential kind round-trip exactly through the persisted context for all three legitimate routing configurations, with a genuine end-to-end GHES SCIM collection/replay round trip | Passed |
| Credential-kind/enterprise-provenance replay fixtures (`NewReplayCollectionClient` preserves an explicitly configured credential kind so a live-collection ClassicPAT gate like `FetchEnterpriseSCIMUsers`'s is not falsely blocked on replay, and defaults an unspecified kind to `NoCredential` rather than inventing a stronger one) | Passed |
| Parent's own 5th overlay gate, ported as a permanent fixture (a genuine, immutable, digest-verified evidence page whose actual content is unrelated to the claimed derived fact must not let that claim verify as true) | Passed |
| Source-provenance/forged-evidence fixtures (`VerifyReportEvidence` proves genuinely persisted evidence and rejects a forged/never-collected outcome; a vacuous zero-evidence/zero-outcome "claims analysis" report is explicitly rejected, not vacuously accepted; a genuinely empty report is explicitly allowed; `ghqr assess evaluate --evidence-dir` CLI refusal and acceptance paths) | Passed |
| Secondary-gate fixtures (GOV-070/SEC-043/SEC-099 confirm IMPLEMENTED when their secondary metric is genuinely measured and passing, and correctly stay NOT_ASSESSED with an explicit ambiguous/unmapped disclosure — never an invented PARTIAL — when the secondary is confirmed-failing; GOV-072's bespoke two-variable matrix confirms PARTIAL via its literal OR clause and reports its one remaining textually-unmapped cell as ambiguous) and the COL-027/COL-001/PRD-016/PRD-029/SEC-016 evaluators (OR-compound tiers, exact-boundary gating, 5-criteria pass/fail counts, missing-metric NOT_ASSESSED) | Passed |
| Corrected-semantics scoring fixtures: PRD-029 never proposes IMPLEMENTED (the authentication-type AND-clause is permanently unverifiable); PRD-016 never proposes IMPLEMENTED or NOT_IMPLEMENTED (both require a confirmed review answer this run cannot observe; a success rate >=75% always proposes PARTIAL via the rule's own "acceptable but not reviewed" clause, boundary-tested at exactly the strict "<2 min" queue-time ceiling); COL-001 never claims a directly-measured "working hours" figure (the metric is genuinely calendar-elapsed; a reading at/under the rule's own 8h ceiling is disclosed as a sufficient, not measured, bound); SEC-016's owner-count/owner-ratio criterion is evaluated per organization, not pooled (three individually-healthy organizations no longer fail merely because their owner counts sum past the absolute-5 cap) | Passed |
| Threshold-override fixtures (`config.Thresholds` honored through a predicate, its confidence distance-from-floor calculation and its rendered Notes disclosure; an override above the measured value correctly withholds IMPLEMENTED, an override below it correctly confirms IMPLEMENTED) | Passed |
| Export-outcomes-threading fixtures (`summary.md` retains a genuine collection-failure outcome through both the initial `ghqr assess evaluate` pass and a subsequent `ghqr assess confirm` re-export, via the new `LoadCollectionLog` round trip) | Passed |
| Content-addressed `RunCollectionContext` fixtures: a direct, valid-shape, schema-correct on-disk edit to the "latest convenience copy" (`run-context.json`, e.g. changing `lookback_days`) is rejected by `LoadRunCollectionContext`'s own embedded self-digest recomputation, not merely a schema/parse check; two genuine runs into the SAME evidence directory (different `CollectedAt`) both succeed independently with distinct content-addressed refs, and each remains loadable by its own exact ref afterward, while the convenience copy reflects only the most recent | Passed |
| `ContextRef`-as-primary-binding fixtures: a report whose `ContextRef` is tampered to cite a second, independently genuine (never byte-edited) context -- written for a different organization -- is rejected by `contextAuthorizesScope`, not silently accepted because the cited ref itself resolves and self-verifies cleanly; `RunVerticalSlice` itself (not just the CLI) captures and binds this context as part of its own success contract | Passed |
| Current-configuration scope-authorization fixtures (`RunVerifiedOfflineEvaluation` rejects a report/context claiming organizations beyond what the CURRENT caller's own `config.ResolvedTargets()` authorizes, before evidence verification or replay ever runs, so a forged or stale report/context can never implicitly "unlock" evaluation of extra scope) | Passed |
| Exact raw-page replay fixtures (`VerifyReportEvidence`'s integrity loop now binds each outcome's own cited `EvidenceRefs` object pair directly -- scope/collector/page-qualified-feature/active-profile identity all re-checked against the outcome's own claim -- instead of a logical `(scope, collector, feature)` manifest lookup that could resolve to whatever a later, unrelated run moved that same logical key to point at; a forged outcome with a page-count/reference-count mismatch, a wrong scope/collector/feature/profile citation, is rejected; legacy outcomes predating `EvidenceRefs` still fall back to the logical lookup, their only genuine binding) | Passed |
| Replay `Availability` fidelity fix (`collectFromReplay` previously forced every loaded page's `Availability` to `Available` regardless of its own recorded HTTP status, so a replayed non-2xx page -- for example a confident 404 a concurrently developing collector branches on -- could not be told apart from a replayed 200; now derives it via the identical `responseAvailability(status, body)` call the live collection path itself uses, falling back to `Available` only for status-less imported evidence) | Passed |
| Exact historical reconstruction fixtures: `ReplayVerticalSlice` now materializes a throwaway, exact-ref-seeded `EvidenceStore` (`materializeExactReplaySource`) from a report's own cited `EvidenceRefs` BEFORE constructing its replay `CollectionClient`, so `collectFromReplay`'s own unmodified logical-key lookup resolves against a frozen, historically-exact source rather than the live evidence directory's own mutable, movable per-feature manifests; two genuine collection runs into the SAME evidence directory/organization, where the second run's own `org.repos` page genuinely overwrites the first run's manifest at the identical logical key, both independently replay to their own exact historical repository inventory (one repository vs. two), cross-checked against each other to confirm the two histories were never conflated, with both context refs remaining independently loadable afterward; seeding also cross-checks each resolved page's own recorded profile/credential-kind identity, not just scope/collector/feature | Passed |
| Stripped-refs hard-gate fixture: a genuinely context-bound report whose own org.repos outcome has its `EvidenceRefs` set to nil (`Pages` left unchanged -- simulating refs stripped after the fact) is rejected outright by both `ReplayVerticalSlice` and `VerifyReportEvidence`, even after a later, genuine run has moved that exact logical manifest key to different content -- never silently falls back to a best-effort logical lookup that would launder the later run's data through the earlier report's claimed identity; a context-bound report's nonzero-page outcome missing `EvidenceRefs` can only mean they were stripped, never a legitimate legacy gap, so it is always a hard failure, not a best-effort fallback | Passed |
| Duplicate-outcome-identity and profile-version parity fixtures: two outcomes/pages resolving to the same logical (scope, collectorID, feature) identity but citing different, conflicting content are rejected as an ambiguous duplicate rather than resolved by whichever is seeded last; `ProfileVersion` (not just `ProfileSHA256`) is cross-checked alongside `CredentialKind` in both the exact-ref seeding path and the separate integrity-check path | Passed |
| Tightened `AnalysisVerified` contract fixtures: a context-less report (`TestVerifyReportEvidenceEmptyContextLessReportNeverEarnsAnalysisVerified`, replacing the prior, now-outdated genuinely-empty-report test) never earns a blanket `AnalysisVerified`/`Verified=true` even when it claims nothing at all and its own replay comparison is trivially clean -- `IntegrityVerified` alone stays honestly true (nothing to disprove), but only a genuinely bound context can earn the overall pass; a context-bound report that claims computed analysis but had zero pages independently verified also cannot earn `AnalysisVerified=true` merely because its replay comparison happens to be vacuously clean | Passed |
| Ref-less report context-binding fixtures: a report with an empty `ContextRef` is now ALWAYS treated as genuinely context-less for replay purposes, even when the evidence directory happens to contain some other run's context file -- multi-run/multi-context storage being first-class now means a directory's "latest" context can easily belong to a different run than the one that produced a given ref-less report, so it is never silently attached | Passed |
| New typed-evaluator fixtures (`ARC-093`/`ARC-104` shared 3-criteria pass/fail count, owner cap-or-ratio evaluated per organization never pooled, missing-metric `NOT_ASSESSED`, and a known-zero one signal paired with a wholly unmeasured other signal never counted as a confirmed criterion failure; `SEC-132`/`GOV-065` never invent a tier from a single known metric when the rule's OTHER mandatory clauses remain genuinely unmeasured -- both stay explicit `NOT_ASSESSED` in every case given today's collector surface, `GOV-065`'s literal 5-10%/>10% bands still independently determining genuine PARTIAL/NOT_IMPLEMENTED when the ratio itself falls within them) | Passed |
| Comprehensive scope-authorization fixtures: `targetsAuthorizeScope` now also checks candidate HOST membership itself (a bare host-only claim for a host the authority never mentions is rejected, not vacuously accepted because its empty organization/enterprise lists have nothing to individually check); a new `deriveClaimedScope` replaces `legacyDeriveReplayTargets` for every scope-AUTHORIZATION call site (current-config gate, bound-context gate), deriving candidates from every outcome's own Scope (organization/repository/enterprise) and every per-organization metric key, not only `report.Organizations`/`report.Targets` -- a report with zero Organizations entries but one outcome scoped to an unauthorized organization is rejected | Passed |
| Replay-comparison hardening fixtures: `compareMetricMaps` now walks the union of claimed+replayed keys and compares both `Overall` and every `PerOrganization` entry (a per-organization value tampered while the pooled sum coincidentally stays correct is caught); a claimed-Known value silently downgraded to Unavailable is now its own explicit mismatch, not silently skipped; `metricValuesEqual` now requires EXACT float equality on `Number`/`Numerator`/`Denominator`/`Baseline`/`Current` (not any tolerance -- the underlying computation is fully deterministic and Go's own `encoding/json` round-trips a `float64` bit-for-bit, so any nonzero epsilon is an arbitrary magic number that could hide a threshold-adjacent tamper), replacing first a 0.01 then a 1e-6 tolerance in successive rounds; `compareOrganizationPopulations` now also checks `Critical.Method` and the `Sample` record; a new `compareOrganizationOperational` (full-struct) and `compareRepositoryResult` (DefaultBranch plus a zero-then-DeepEqual catch-all for every other repository sub-result) close the remaining gaps | Passed |
| Terminal-pagination-proof fixtures: `EvidenceMetadata.PaginationContinues` is a tri-state `*bool` (not a plain `bool`) recorded once per page at collection time from a read-only peek at that page's own Link header: true only when a valid `rel="next"` was genuinely present (regardless of whether that next page was later fetched successfully); false only when the page was validly checked and genuinely carried none, or pagination was never requested for that call at all (explicit for GraphQL/non-paginated single fetches); nil for everything else (a pre-this-field legacy page, or one whose Link header could not even be parsed -- a malformed/cross-origin link is never silently coerced to false). `pageProvablyTerminal` is the one gate trusting this proof (only a confirmed false counts; nil is never treated as an equivalent to false), letting `materializeExactReplaySource` catch a genuine two-page partial outcome (page1 OK with a next link, page2 denied) truncated down to a false one-page `CollectionOK`/`Complete:true` claim, from the last cited page's own immutable metadata -- never a directory-presence/page-count heuristic | Passed |
| Frozen-clock consolidation fixtures: `runVerticalSliceWithStore` now reads its own clock exactly once and reuses that single value for `report.CollectedAt` and every lookback/alert-window/population-cutoff computation (previously up to three independent `clock.Now()` reads per run, each genuinely drifting by microseconds); `ReplayVerticalSlice` seeds its own replay invocation -- both `runVerticalSliceWithStore`'s own clock parameter and the replay `CollectionClient` factory's clock -- with a single `frozenClock` pinned to the ORIGINAL run's own `CollectedAt`/bound context `CollectedAt`, never a fresh wall-clock read; this makes every "now"-derived claim (for example an audit log's own requested lookback window) genuinely, exactly reproducible across a replay pass, closing the gap the prior round's `AuditLogResult.RequestedSince`/`RequestedUntil` exception had only worked around | Passed |
| Immutable original-outcomes-inventory fixtures: `RunCollectionContext.OriginalOutcomes` binds the run's own complete, verbatim `CollectorOutcome` list (captured by `RunVerticalSlice` the moment collection finishes, via a new `WriteRunCollectionContextWithOutcomes`) alongside every other context field under the SAME self-digest -- the only place a zero-page outcome (a transport failure before any HTTP response was even observed, a permission-denied organization) can ever be independently proven genuine, since it has no persisted evidence pages for `compareVerticalSliceReports`/the per-page integrity loop to check its own Reason/Status text against; `ReplayVerticalSlice` now rejects a context-bound report's own claimed Outcomes if they diverge from this bound inventory in ANY field, or omit/add an entry entirely; `RunVerifiedOfflineEvaluation` uses this now-independently-proven claimed `report.Outcomes` for collection-log/export reporting (never the replayed reconstruction's own outcomes, which can only ever synthesize a generic substitute for a zero-page feature), while scoring remains the canonical, independently replayed analysis throughout | Passed |
| Config-only/outcomes-unbound context downgrade fixtures: a context carrying NO bound `OriginalOutcomes` at all (written via the plain `WriteRunCollectionContext`, or genuinely predating this mechanism) is an explicit compatibility downgrade, never a silent pass -- a report claiming ANY zero-page outcome under such a context is a hard replay refusal (nothing in the pipeline could ever independently prove that specific claim), propagating through `VerifyReportEvidence` to `AnalysisVerified=false`/`Verified=false` and through `RunVerifiedOfflineEvaluation` to an outright refusal, never a blind copy of the supplied (unproven) Outcomes into the exported collection-log; a report with no zero-page outcomes under such a context is unaffected (every one of its outcomes has real pages for the existing comparisons to check instead) | Passed |
| ImportOnly bare-feature replay fixtures: `materializeExactReplaySource` now special-cases `Readiness: ImportOnly` outcomes (ghes.cli/ghes.backup, every `ui.*`/`ext.*` capture, `manual.interview`/`manual.document`) to their own bare feature-name identity (never the REST `pageFeatureName` "-page-NNNNNN" suffix convention a live `CollectGET` call always produces) and exempts them from the terminal-pagination-proof check entirely (a single, complete imported record has no "next page" concept to prove absent) | Passed |
| OAuth user credential-kind fixtures: `OAuthUser` (a GitHub OAuth App user-to-server `gho_` token) is a new, truthfully distinct `CredentialKind` using the identical Bearer read-only transport as `ClassicPAT`/`FineGrainedPAT` -- accepted by customer config validation and evidence metadata validation, preserved exactly (never relabeled as `ClassicPAT`) through `NewReplayCollectionClient`, and still correctly excluded by SCIM's own pre-existing `!= ClassicPAT` exclusionary gate (zero requests attempted) | Passed |
| CLI verification-truthfulness fixtures: `evaluate` requires exactly one of `--evidence-dir`/`--allow-unverified` (mutually exclusive, no silent-trust default) and an explicit `--out` with no default, refusing to overwrite an existing canonical result set (`evaluation-results.json`) unless `--overwrite` is set, verified via dedicated negative/no-files-written fixtures; `--allow-unverified` persists `verification-status.json` (`VerificationModeUnverifiedConsent`) inside the SAME atomic export batch as every other artifact and prepends an explicit "UNVERIFIED supplied analysis" disclosure to `summary.md`; `confirm` loads and preserves the original verification mode unchanged (never upgrades it) across a re-export | Passed |

The local default Go 1.27.1 toolchain caused the pinned Go-1.26-built linter to
panic. Selecting the `go.mod` toolchain for the command fixes this without changing
global settings or the Makefile. Use `GOTOOLCHAIN=go1.26.0 make test` on that host.

The initial local-build request did not publish changes. The user subsequently
authorized publishing only the feature branch to `arnaudlh/ghqr`; origin and
branch inspection confirmed that fork target. Safe collection and
evidence/replay, the contractual export mappers, the inventory/rules/
workflows vertical slice, and now a deterministic typed evaluator registry
(fifteen control IDs; see the section above), its GOV-070 missing-one-rule-type
widening clause, secondary-gate confirmation/ambiguous-disclosure for the
compound evaluators (including GOV-072's own bespoke two-variable matrix,
and the same `orMatrixTier` pattern generalized for `COL-001`),
customer-accepted threshold-override support, full-pipeline raw-evidence
replay (see above; superseding the earlier per-collector-only approach),
explicit assessor confirmation and a fully offline evaluate/confirm export
pipeline are implemented and locally verified. **This remains open,
in-progress work, not a completed phase**: the four secondary metrics the
first round of compound evaluators needed
(`org_default_branch_rulesets_active`, `verified_commit_ratio_pct`,
`repos_with_grouped_version_updates_pct`,
`repos_with_actions_ecosystem_updates_pct`), and a later round's corrected
exact-named metrics (`default_repository_permission`, `owner_count`,
`owner_ratio_pct`, `repos_with_direct_collaborators_pct`,
`outside_collab_ratio_pct`, `members_without_2fa`,
`review_coverage_pct`/`median_time_to_first_review_h`,
`ci_success_rate_90d`/`median_queue_time_min`, `hooks_without_secret_pct`/
`hooks_insecure_ssl_count`), all landed from the concurrently developing
collector work under their exact profile-declared names and are now wired
into `COL-001`/`COL-027`/`PRD-016`/`PRD-029`/`SEC-016` plus the four original
compound evaluators; a further re-scan against that same expanding
collector work's metric keys found these new resolvable controls and
fourteen-plus more explicitly considered and deferred for documented reasons
(see above) rather than silently skipped. An independent review round
reproduced and fixed three real regressions in this same code (an invented
PARTIAL downgrade the rules never defined, a vacuous evidence-verification
pass on zero actual evidence, and a summary export that silently dropped
real collection failures) plus a threshold-override gap; a subsequent round
found the then-current workflow-only replay insufficient and replaced it
first with genuine raw-evidence replay through
`ComputeEffectiveBranchProtection`/`AnalyzeRepositoryWorkflows` directly, and
then -- when that too was judged a narrowed helper, not genuine full
replay -- with the full-pipeline `ReplayVerticalSlice` described above; a
later round found that mechanism's `RunCollectionContext` binding itself
insufficiently immutable (a single fixed-path, non-digest-verified file
both accepted valid-shape tampering and could not support a second genuine
run into the same evidence directory), replaced with a content-addressed,
self-digesting design whose ref is now captured by `RunVerticalSlice`
itself as part of its own success contract (not left to CLI-only
after-the-fact writing), gained a current-configuration scope-authorization
gate in `RunVerifiedOfflineEvaluation`, and had its evidence-integrity loop
rebound to each outcome's own cited `EvidenceRefs` object pair rather than
a movable logical-key lookup -- and, when that integrity-binding alone was
judged insufficient for genuine PIPELINE reconstruction (not just
after-the-fact verification), extended into `ReplayVerticalSlice` itself:
a throwaway, exact-ref-seeded `EvidenceStore` is now materialized from a
report's own cited `EvidenceRefs` before its replay `CollectionClient` is
even constructed, so the existing, unmodified `collectFromReplay` logical-
key lookup resolves against a frozen, historically-exact source instead of
the live evidence directory's own mutable manifests, proven by two genuine
runs into the same directory/organization whose repository inventories
each remain independently, correctly reconstructable after the second
run's own page overwrites the first run's shared logical ref; a ref-less
report was also found to incorrectly inherit ContextBound=true from
whatever context happened to be "latest" in the directory, fixed so only a
report's own cited ref ever earns that; see
the phase-notes file's Round 4 through Round 9 sections for full detail.
The remaining 244 of 259 Full/Partial controls' automatic rules and the
broader collector/metric catalogue beyond what `ghqr assess run` and its
typed evaluators consume remain open; neither is implemented or verified
yet. Fifteen genuinely implemented evaluators is not an approximation of the
profile's 150 Full-automation controls, and `results.csv` always containing
456 rows must never be read as 456 controls having been scored.


A production performance benchmark requires an explicitly supplied safe target.
Fixture timing cannot establish production acceptance.
