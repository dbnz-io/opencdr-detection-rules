# OpenCDR Detection Rules

Detection rule content for [OpenCDR](https://github.com/dbnz-io/opencdr) — CloudTrail/GuardDuty
signal rules, cross-source correlation rules, and reference lists. This repo holds **rule
content only**: the detection engine that parses events and evaluates these rules (normalization,
matching, correlation windows) lives in the main OpenCDR codebase, which consumes this repo as a
git submodule at `support_files/detection_rules`.

Licensed under [MIT](LICENSE) — deliberately more permissive than the main codebase (MPL 2.0), since
rule content benefits from being as easy as possible to fork, adapt, and redistribute.

## Layout

Rules live one folder per event source, mirroring how the consuming engine's parsers are organized:

```
cloudtrail/    19 signal rules + 4 pure-CloudTrail correlation rules
guardduty/     5 signal rules (4 curated families + 1 catch-all)
correlation/   2 cross-source correlation rules (span CloudTrail + GuardDuty)
```

Adding a new event source (GitHub audit log, Falco, etc.) means adding a new top-level folder the
same way — every loader in the consuming repo scans recursively, so a new folder needs no code
change on that side to be picked up.

Three fixture-only stub files (`test_atomic_rule.json`, `test_correlation_rule.json`,
`test_detection_rule.json`) stay at the top level, are not source-organized, and are always
skipped by every loader — they're example/template shapes, not real rule content.

## Signal rules

Matches a single normalized event. When every condition passes, a signal is written.

```json
{
  "rule_id": "001_console_login_no_mfa",
  "rule_kind": "signal",
  "description": "Console login without MFA.",
  "enabled": true,
  "severity": "HIGH",
  "notify": true,
  "response_module": "",
  "playbook": "Verify user and source IP. If suspicious, revoke sessions and enforce MFA.",
  "conditions": [
    { "field": "activity_name", "op": "equals", "value": "ConsoleLogin" },
    { "field": "raw_event.detail.additionalEventData.MFAUsed", "op": "equals", "value": "No" }
  ]
}
```

**Operators**: `exists`, `not_exists`, `equals`, `not_equals`, `in`, `not_in`, `in_list`, `not_in_list`
(membership against a `rule_kind: "list"` rule — see [List rules](#list-rules); needs a `list_id`
instead of `value`), `contains`, `not_contains`, `prefix`, `not_prefix`, `suffix`, `not_suffix`,
`matches`, `not_matches` (regex), `wildcard` (matches any event, no `value` needed).

**Normalized fields available in conditions** (produced by the consuming repo's
`src/domain/ocsf_min_parser.py`):

| Field | Description |
|---|---|
| `activity_name` | CloudTrail event name (e.g. `ConsoleLogin`, `CreateUser`) |
| `category` | Event category derived from service (e.g. `iam`, `s3`, `ec2`, `authn`) |
| `class_name` | Event class (`api_activity`, `authentication`, `security_finding`) |
| `source` | Event source (`cloudtrail`, `guardduty`) |
| `severity` | Normalized severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) |
| `gd_resource_type` | GuardDuty only: the `ResourceType` segment of the finding's `Namespace:ResourceType/ThreatPurpose` type string (e.g. `IAMUser`, `EC2`, `S3`). `None` for CloudTrail events. |
| `actor.type` | Identity type (`Root`, `IAMUser`, `AssumedRole`, `FederatedUser`) |
| `actor.user_name` | IAM principal name |
| `actor.account_id` | AWS account ID of the actor |
| `actor.arn` | Full ARN of the actor |
| `network.source_ip` | Source IP address |
| `network.user_agent` | User agent string |
| `api.service` | AWS service endpoint (e.g. `iam.amazonaws.com`) |
| `api.operation` | API operation name |
| `api.error_code` | CloudTrail error code if the call failed |
| `raw_event.detail.*` | Any field from the raw EventBridge event payload, if you need something not yet normalized |

If `response_module` is set on a signal rule (e.g. `disable_access_key`), a match also queues an
automated IR action in the consuming repo — see its
[Incident Response](https://github.com/dbnz-io/opencdr/blob/main/docs/incident-response.md) doc.

## GuardDuty rules

GuardDuty findings are normalized into the same shape as CloudTrail events, with one addition:
`gd_resource_type` (see the fields table above). Rather than curate all ~100+ GuardDuty finding
types individually, this repo ships **4 curated rules** for the families worth an automated
response, plus **1 catch-all** (`028_guardduty_catchall`) that gives every other Medium+/High/Critical
finding visibility (no automated response) without hand-writing a rule per finding type.

Worked example — `024_guardduty_iam_credential_compromise.json`:

```json
{
  "rule_id": "024_guardduty_iam_credential_compromise",
  "rule_kind": "signal",
  "severity": "HIGH",
  "notify": true,
  "response_module": "disable_access_key",
  "conditions": [
    { "field": "source", "op": "equals", "value": "guardduty" },
    { "field": "gd_resource_type", "op": "equals", "value": "IAMUser" },
    {
      "field": "activity_name",
      "op": "matches",
      "value": "^(UnauthorizedAccess|CredentialAccess):IAMUser/(TorIPCaller|MaliciousIPCaller(\\.Custom)?|CompromisedCredentials|InstanceCredentialExfiltration\\.(InsideAWS|OutsideAWS)|ResourceCredentialExfiltration\\.(InsideAWS|OutsideAWS)|ConsoleLoginSuccess\\.B)$"
    }
  ]
}
```

Every curated rule follows the same shape: `source == guardduty`, optionally `gd_resource_type`,
and a `matches`/`prefix` regex against `activity_name` (GuardDuty's finding `type` string) narrow
enough to exclude lower-confidence findings in the same family (e.g. `024` excludes brute-force
*attempts* — those aren't confirmed compromise, and firing `disable_access_key` on a mere attempt
is a needless disruption). The 5 shipped rules:

| Rule | `gd_resource_type` | Matches | `response_module` |
|---|---|---|---|
| `024` IAM credential compromise | `IAMUser` | Tor/malicious-IP callers, compromised/exfiltrated credentials, brute-forced console login | `disable_access_key` |
| `025` EC2 backdoor/malware | `EC2` | `Backdoor`/`CryptoCurrency`/`Trojan` findings | `isolate_ec2_instances` |
| `026` S3 exposure/exfiltration | `S3` | Public-access-granted policy findings, anomalous/malicious-IP exfiltration findings | `block_s3_bucket_public_access` |
| `027` Attack Sequence | — (multi-resource) | `AttackSequence:` prefix (AWS's own multi-signal correlation output, fixed Critical severity) | *(none — see below)* |
| `028` Catch-all | — | `source == guardduty`, severity in `[MEDIUM, HIGH, CRITICAL]`, and none of 024/025/026/027's patterns | *(none)* |

`027` deliberately has no `response_module`: an Attack Sequence finding's affected-resource shape
is a multi-resource list, not the single-resource shape the other curated rules and their response
modules assume. It still fires — visibility at Critical severity — but which resource to act on
isn't safely inferable yet.

Notification is a separate decision from matching: all 5 rules set `notify: true` so every match is
always written to the alerts table, but GuardDuty items default to **not sending** a notification
in the consuming repo's settings.

### Keeping this in sync

`028`'s catch-all conditions explicitly exclude each curated rule's match pattern via
`not_matches`/`not_prefix` (mirrored, negated copies of `024`-`027`'s conditions). This is necessary
because the detection engine returns *every* matching rule, not first-match-wins — an unfiltered
catch-all would double-fire alongside every curated rule, producing two signals for one real finding.

**If you add or edit a curated GuardDuty rule's `activity_name` pattern, update
`028_guardduty_catchall.json`'s matching exclusion condition in the same change** — otherwise the
finding type either double-fires (pattern narrowed without updating the exclusion) or silently
stops appearing anywhere (pattern widened without updating the exclusion). Each of `024`-`027`
carries a non-functional `_sync_note` field pointing back here as a reminder — matching only reads
`conditions`, so the note itself has no effect. The consuming repo's `tests/domain/test_guardduty_rules.py`
asserts each curated finding fires exactly one rule and that uncovered findings fire only the
catch-all; that suite runs against whatever commit of this repo it has checked out, so a PR here
that breaks the invariant will fail there, not here — see [Contributing](#contributing).

**Explicitly out of scope for now**: normalization of GuardDuty's `dnsRequestAction`/`portProbeAction`/
`kubernetesApiCallAction`/RDS-login/Lambda-resource action shapes — none are needed by the 4 curated
families above, and adding them speculatively would be work against an unbounded, AWS-controlled
action-shape surface.

## Correlation rules

Groups signals by a field, counts them within a rolling time window, and fires an alert once the
threshold is met. `signal_conditions` optionally restricts which signals count toward the threshold.

```json
{
  "rule_id": "020_correlation_console_login_bruteforce",
  "rule_kind": "correlation",
  "description": "Multiple MFA-less logins from the same user.",
  "enabled": true,
  "severity": "CRITICAL",
  "group_by": "actor.user_name",
  "time_window_seconds": 900,
  "threshold": 5,
  "signal_conditions": [
    { "field": "rule_id", "op": "equals", "value": "001_console_login_no_mfa" }
  ],
  "notify": true,
  "response_module": "disable_user",
  "playbook": "Disable the user and investigate source IPs."
}
```

`group_by` matters for performance, not just logic: the consuming repo's correlation engine queries
a GSI when grouping by `actor.user_name` (most shipped correlation rules do), and falls back to a
full table scan for any other `group_by` value.

### Cross-source correlation

`group_by`/`signal_conditions` don't care which parser produced a signal — `rule_id` is just
another field on the stored signal, and a `signal_conditions` list can mix rule IDs from different
sources freely. Two shipped rules prove this, both in `correlation/` (a folder alongside
`cloudtrail/`/`guardduty/`, for rules that span more than one source — the 4 pure-CloudTrail
correlation rules `020`-`023` stay in `cloudtrail/`, since they don't):

- **`029_correlation_guardduty_credential_compromise_then_privesc`** — a GuardDuty credential-compromise
  finding (`024`) followed by a CloudTrail admin-policy attach (`009`) from the *same*
  `actor.user_name`. Uses the existing GSI — GuardDuty's parser populates `actor.user_name` for
  IAM-related finding types, so this needs no new indexing. `response_module: "disable_user"` is
  safe to wire live here, since `actor.user_name` is the same field the CloudTrail-only correlation
  rules already resolve correctly in production.
- **`030_correlation_guardduty_backdoor_then_secrets_access`** — a GuardDuty EC2 backdoor/C2 finding
  (`025`) and a CloudTrail `GetSecretValue` call (`016`) from the same `network.source_ip` — the
  first shipped rule to use the scan-fallback path instead of a GSI. Deliberately
  `response_module: ""` — the correlation alert's primary signal may end up being the GuardDuty
  finding, which has no IAM-user resource for the automated-response username lookup to find, so an
  automated action here could silently no-op on a real fraction of firings. Visibility-only until
  that's worth solving properly.

Both `threshold`/`signal_conditions` combinations are a coarse **count**, not a strict one-of-each
— e.g. rule `029`'s `threshold: 2` over a 2-item `rule_id` list would in principle also fire on two
`024`s with no `009` at all. This is an existing engine-wide property (rule `022` already has the
same shape, 4 rule_ids/threshold 2), not something specific to cross-source rules.

## List rules

A static value list other rules reference by ID via `in_list`/`not_in_list` — not itself a
detection rule, no `conditions`/`severity`/`response_module`.

```json
{
  "rule_id": "automation-identities",
  "rule_kind": "list",
  "values": ["ci-deploy-role", "terraform-apply", "cdk-toolkit"]
}
```

```json
{ "field": "actor.user_name", "op": "not_in_list", "list_id": "automation-identities" }
```

`list_id` must match a `list` rule's `rule_id`. No shipped rules use this yet — it exists so you
can build your own exclusion lists (e.g. CI/CD or IaC identities that would otherwise trip a
correlation rule tuned for human behavior).

## What ships out of the box

24 signal rules (19 CloudTrail-sourced + 5 GuardDuty-sourced) and 6 correlation rules
(4 pure-CloudTrail + 2 cross-source), covering initial access, persistence, privilege escalation,
defense evasion, credential access, and exfiltration.

### Signal rules

| Rule | Severity | Tactic |
|---|---|---|
| `001` Console login without MFA | HIGH | Initial Access |
| `002` Root account used for any action | CRITICAL | Privilege Escalation |
| `003` Root account console login | CRITICAL | Initial Access |
| `004` Root access key created | CRITICAL | Persistence |
| `005` IAM user created | MEDIUM | Persistence |
| `006` Access key created | MEDIUM | Persistence |
| `007` IAM role created | MEDIUM | Persistence |
| `008` Lambda function created or updated | MEDIUM | Persistence |
| `009` AdministratorAccess policy attached | CRITICAL | Privilege Escalation |
| `010` Wildcard inline policy created | HIGH | Privilege Escalation |
| `011` Security group ingress rule added | MEDIUM | Defense Evasion |
| `012` CloudTrail stopped, deleted, or updated | CRITICAL | Defense Evasion |
| `013` GuardDuty detector deleted or disabled | CRITICAL | Defense Evasion |
| `014` AWS Config recorder stopped or deleted | HIGH | Defense Evasion |
| `015` Security Hub disabled | HIGH | Defense Evasion |
| `016` Secrets Manager secret accessed | HIGH | Credential Access |
| `017` SSM parameter accessed | MEDIUM | Credential Access |
| `018` S3 bucket made public | HIGH | Exfiltration |
| `019` RDS snapshot made public | HIGH | Exfiltration |
| `024` GuardDuty IAM credential compromise | HIGH | Credential Access |
| `025` GuardDuty EC2 backdoor/malware | HIGH | Command and Control |
| `026` GuardDuty S3 exposure/exfiltration | HIGH | Exfiltration |
| `027` GuardDuty Attack Sequence | CRITICAL | Multiple (AWS-correlated) |
| `028` GuardDuty catch-all (uncurated findings, visibility only) | MEDIUM | — |

### Correlation rules

| Rule | Severity | Description |
|---|---|---|
| `020` Console login brute force | CRITICAL | 5+ MFA-less logins from same user in 15 min |
| `021` IAM activity burst | CRITICAL | 5+ IAM signals from same actor in 5 min |
| `022` Defense evasion burst | CRITICAL | 2+ logging/detection services disabled in 10 min |
| `023` Credential harvesting | CRITICAL | 3+ secrets/SSM accesses from same actor in 5 min |
| `029` GuardDuty credential compromise → privilege escalation *(cross-source)* | CRITICAL | Same actor: GuardDuty-flagged compromised credential, then admin policy attached, within 15 min |
| `030` GuardDuty backdoor → secrets access *(cross-source, visibility only)* | HIGH | Same source IP: GuardDuty backdoor/C2 finding, then Secrets Manager access, within 15 min |

## How these rules get consumed

[dbnz-io/opencdr](https://github.com/dbnz-io/opencdr) pulls this repo in as a git submodule at
`support_files/detection_rules`, pinned to a specific commit. Its `scripts/load_rules.sh` and
`scripts/opencdr.py rules load` both do a plain recursive scan + upsert of everything here into a
running deployment's DynamoDB detection-rules table; `scripts/test_rules_local.py` runs every rule
here against sample events without touching AWS. Bumping the submodule pin (`git submodule update
--remote support_files/detection_rules` from the consuming repo, then commit the pointer change) is
how a change here reaches a deployment — merging a PR to this repo alone does not.

## Contributing

New rules are the highest-value contribution. To add one:

1. Add the rule JSON here, in `<source>/` (e.g. `cloudtrail/`, `guardduty/`; add a new source
   folder the same way if the rule doesn't fit an existing one), following the naming convention
   `NNN_rule_name.json` — pick the next unused number.
2. Open a PR here with the rule and a description of the attack pattern it covers.
3. Separately, open a companion PR to [dbnz-io/opencdr](https://github.com/dbnz-io/opencdr) adding
   a matching test event fixture under `support_files/test_events/NNN_event_name.json` and bumping
   this repo's submodule pin, so `scripts/test_rules_local.py` can actually exercise the new rule.
   This second PR is what proves the rule fires — a rule-only PR here can't be verified against the
   real detection engine, since that code doesn't live in this repo.

If you're only touching an existing rule's conditions (not adding a new one), a PR here plus a bump
of the submodule pin on the consuming side is enough — no new fixture needed unless the rule's
matching behavior changed in a way existing fixtures don't cover.
