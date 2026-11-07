# Fix effort

HorusEye rates every finding and every proposed fix by **effort**: how hard
the fix is to make. It sits next to severity, which says how bad the problem
is. The two answer different questions, so they are kept apart:

* **Severity** (Critical, High, Medium, Low) comes from the detector: what an
  attacker gets.
* **Effort** (Low, Medium, High) comes from the rules below: time to apply the
  fix, plus who feels it when you do (blast radius).

Effort never changes severity, and severity never changes effort. A test
checks that rating effort leaves every severity exactly as it was.

A **Quick Win** is a finding that is **Critical or High** severity **and**
**Low** effort. Quick Wins are listed first in every output, best first:
the most users cut off from Tier-0, then the most users with a route through
the finding, then whether it is on a route at all, then score.

The rules are deterministic: the same data gives the same rating every run.
No AI is involved. Each rating carries a plain reason, and the id of the rule
that produced it, so you can disagree with it in the open.

## Rules for one change

A change removes one relationship from the attack graph, for example "remove
HELPDESK's password-reset right on SVC-BACKUP". The first matching rule wins.

| Rule | Change | Effort | Why |
|---|---|---|---|
| `effort.delegation` | Unconstrained, constrained or resource-based delegation | High | Services that rely on delegation can stop authenticating. Plan and test. |
| `effort.gpo_link` | A GPO's link, when the GPO applies to 3 or more objects | High | Changing it touches every object it applies to. Medium below 3. |
| `effort.sync_account` | DCSync held by a directory sync account (`MSOL_`, `AAD_`, `SYNC_`, `ADSYNC` prefixes) | High | Entra Connect and similar tools need replication; move them to a supported, protected setup rather than removing the right. |
| `effort.dcsync` | DCSync held by any other account | Low | Nothing legitimate needs it outside domain controllers and sync services. |
| `effort.membership` | Removing a member from a group | Medium | The member loses everything the group grants, not just this route. |
| `effort.session` | A privileged account signed in where it shouldn't be | Medium | Changes how an admin works: sign out, then enforce tiering with a deny-logon policy. |
| `effort.adcs_template` | A certificate template or CA permission | Medium | Everyone who enrolls in that template is affected. Test enrollment. |
| `effort.app_fix` | A web app that runs code as its service account | Medium | A code or configuration fix in the app; test the app. |
| `effort.sid_history` | SID history on an account | Medium | Clear it once the migration it came from is confirmed finished. |
| `effort.tier0_permission` | A permission whose target is Tier-0 | Medium | Use your change process for Tier-0 objects. |
| `effort.permission` | Any other permission (ACL, password reset, add member, local admin, LAPS or gMSA reader) | Low | One permission on a non-Tier-0 object; nothing else depends on it. |
| `effort.default` | Anything without a specific rule | Medium | Review before applying. |

Then one adjustment:

| Rule | When | Effort | Why |
|---|---|---|---|
| `effort.service_account` | The change takes access away from a service account (it has an SPN, a web app runs as it, or its name starts with `SVC-`, `SRV-`, `SA-`, `SQL-`, `APP-`, `IIS-`, `SERVICE-`) | at least Medium | The service may break. Test first. |

The adjustment applies to access the service account **holds**. Removing
someone else's right **over** a service account (for example HELPDESK's
password-reset right on it) doesn't touch what the app does, so it stays Low.
The name prefixes are a heuristic; an SPN or a web app mapping is evidence.

## Rules for a finding

A finding is linked to the attack-graph relationships its evidence names. Its
effort is the hardest of those changes, then:

| Rule | When | Effort |
|---|---|---|
| `effort.many_changes` | The fix is more than 10 separate changes (for example, one per host) | High: plan a rollout |
| `effort.many_changes` | 3 to 10 separate changes, otherwise Low | Medium |

and never below the finding type's minimum:

| Rule | Finding type | Minimum |
|---|---|---|
| `effort.delegation` | Unconstrained or constrained delegation | High |
| `effort.trust` | Domain trust | High: every user and app crossing the trust is affected |
| `effort.domain_policy` | Weak domain password policy | High: every user at their next password change |
| `effort.adcs_relay` | ADCS ESC8 or ESC11 (relay to the CA) | High: the CA's web or RPC enrollment changes for every client |
| `effort.service_account` | Kerberoastable account | Medium: rotate to a long random password or a gMSA, and update the app |
| `effort.session` | Privileged session | Medium |
| `effort.gpo_rights` | GPO edit rights | Medium: confirm who manages the GPO first |
| `effort.adcs_template` | Other ADCS findings | Medium |

Findings that are not steps in the attack graph are rated by type alone:

| Rule | Finding type | Effort |
|---|---|---|
| `effort.preauth` | AS-REP roastable account | Low: turn pre-authentication back on (Medium for a service account, `effort.service_account`) |
| `effort.stale_account` | Stale privileged account | Low: disable or remove it |
| `effort.default` | Anything else | Medium |

## Where effort shows up

* The **Quick Wins** section at the top of the CLI, HTML and Markdown output,
  the Overview card and the Quick Wins filter in the explorer, and
  `"quick_win": true` in the JSON.
* Every finding card: "Why it is an easy / a moderate / a hard fix".
* Every fix option, the exposure plan, and the `--keep` alternative: each
  change has its own effort.
* The CSV export: `effort` and `effort_reason` columns.

The rules live in `horuseye/core/effort.py`. If a rating looks wrong for your
environment, open an issue with the finding type and why; the rule and its
reason are meant to be argued with.
