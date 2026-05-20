# silent-updater

Autonomous agent for updating vulnerable Java/Maven dependencies in repositories hosted on **Bitbucket Server / Data Center**.

The agent reads a list of vulnerable libraries from Excel, opens (or clones) the target repo, and iteratively figures out a safe target version for each vulnerability — trying direct bumps, `dependencyManagement` overrides, and exclusion strategies until the regression pipeline passes and the vulnerability is gone from `mvn dependency:tree`.

Most CVEs in real Java projects live in *transitive* dependencies — the agent is built around that fact.

Two modes:

- **`--no-llm` (default recommended for corp use)** — deterministic Python algorithm. No external LLM, no GitHub auth, no proxy needed. **This is the "safe" mode.**
- **LLM-driven** — uses GitHub Models API (`models.github.ai`) via OAuth device flow. Has more flexibility on strategy choice but sends pom contents to an external LLM service. **Read the policy notes below before using.**

---

## Install

```bash
python3 -m pip install -e ".[dev]"
```

You need: Python 3.11+, `mvn` on PATH, `git` on PATH.

If `silent-updater` command isn't found after install (Mac/Linux PATH issue), use the module form everywhere: `python3 -m silent_updater.cli ...`.

---

## Quickstart — deterministic mode (no LLM, no network)

Copy-paste, swap the paths, hit run:

```bash
python3 -m silent_updater.cli run \
    --repo-url "file:///Users/you/IdeaProjects/your-java-project" \
    --pipeline-cmd "mvn clean test" \
    --compliance ./examples/compliance_config.json \
    --vuln-xlsx ./examples/vulnerable_libs.xlsx \
    --workdir /tmp/silent-work \
    --no-llm \
    --dry-run
```

**Big batches (100+ vulnerabilities) — use the two-stage pipeline.** A fast pre-flight catches "doesn't even compile" cases in seconds instead of after the full test run:

```bash
python3 -m silent_updater.cli run \
    --repo-url "file:///Users/you/IdeaProjects/your-java-project" \
    --quick-pipeline-cmd "mvn -q -DskipTests compile" \
    --pipeline-cmd "mvn clean verify -DskipITs" \
    --compliance ./examples/compliance_config.json \
    --vuln-xlsx ./my_vulns.xlsx \
    --workdir /tmp/silent-work \
    --no-llm
```

Each attempt now goes: `quick → if fail rollback else full → verify → commit`. Most version-breakers die in the 30-second quick stage so you don't pay for a 10-minute full test run on them.

First run **always** with `--dry-run` — it shows the plan without modifying anything. Once happy, drop the flag:

```bash
python3 -m silent_updater.cli run \
    --repo-url "file:///Users/you/IdeaProjects/your-java-project" \
    --pipeline-cmd "mvn clean test" \
    --compliance ./examples/compliance_config.json \
    --vuln-xlsx ./my_vulns.xlsx \
    --workdir /tmp/silent-work \
    --no-llm
```

What you get:

- In `/tmp/silent-work/<repo-name>/` — a clone with a new branch (`deps/silent-update-YYYYMMDD`) and one commit per successful update.
- `update_report.md` in the same directory — what got updated, what was skipped, what we gave up on.
- The branch is **not pushed** unless you also pass `--bitbucket-base/--project-key/--repo-slug` and have a Bitbucket PAT stored.

### With Bitbucket PR creation

```bash
# One-time: store your Bitbucket Server HTTP Access Token
python3 -m silent_updater.cli set-bitbucket-token <YOUR_PAT>

# Then in your run, add:
#   --bitbucket-base https://bitbucket.your-bank.local \
#   --project-key PROJ --repo-slug your-repo
```

---

## Inputs

### `vulnerable_libs.xlsx`

The format is auto-detected by header names. Two layouts are supported:

**Standard format:**

| groupId | artifactId | vulnerableVersion | cve | severity | notes |
|---|---|---|---|---|---|
| org.apache.logging.log4j | log4j-core | 2.14.1 | CVE-2021-44228 | CRITICAL | log4shell |

Only `groupId`, `artifactId`, `vulnerableVersion` are required.

**Veracode export:**

Drop in the Excel report as-is. Required columns: `Component name and version` (GAV like `org.foo:bar:1.2.3`) and `Source Ref` (the CVE). Recognised optional columns: `Version`, `Overall Severity` (incl. "Very High" → CRITICAL), `CVE Summary`, `Fixed Version`. Multiple rows for the same `(GA, version)` are merged automatically — CVEs are concatenated, severities collapse to the highest, fixed versions are unioned.

The agent uses `Fixed Version` (if present) as the **first** candidate target, then falls back to `mvn versions:display-dependency-updates`. Veracode's messy `5.19.3, 5.19.3 ? Version ? 5.19.3, 6.2.2 ? Version ? 6.2.2` is parsed by extracting version-shaped tokens.

### `compliance_config.json`

```json
{
  "update_strategy": "patch_minor",
  "exceptions": [{"ga": "org.example:legacy-lib", "reason": "..."}],
  "version_pins": {"org.springframework:spring-core": "<6.0.0"},
  "max_attempts_per_dep": 5,
  "branch_template": "deps/silent-update-{date}",
  "pr_target_branch": "main"
}
```

`update_strategy`: `patch` | `patch_minor` | `any`.

---

## Deterministic algorithm (what `--no-llm` does)

For each vulnerable dep (sorted by severity):

1. Skip if listed in `compliance.exceptions`.
2. `mvn dependency:tree` — if the GA is not in the tree, skip ("not affected").
3. Pick candidate versions: from `mvn versions:display-dependency-updates`, keep those that are strictly greater than the vulnerable version, satisfy `version_pins`, and pass the `update_strategy` filter (patch < minor for `patch_minor` strategy). Sort smallest bump first.
4. Pick strategy chain by location in the tree:
   - **Direct dep** → `[bump_direct_version]`
   - **Transitive dep** → `[add_dependency_management_override, add_exclusion_and_direct]`
5. For each strategy × candidate version (up to `max_attempts_per_dep`):
   - Apply via Maven/lxml. Run the regression pipeline. Verify the vulnerable version is no longer in `dependency:tree`.
   - On success: `git commit`, move on to the next vulnerability.
   - On pipeline fail OR vuln still present: `git checkout HEAD -- <pom>` to roll back the file, log the attempt, try the next candidate.
6. After all vulns: push the branch (if commits exist) and open a Bitbucket PR (if coordinates+PAT provided).

---

## LLM-driven mode

Use this only if you have explicit InfoSec sign-off to send pom.xml content to an external LLM.

```bash
# One-time GitHub OAuth via device flow (browser opens)
python3 -m silent_updater.cli login --client-id <YOUR_GH_OAUTH_APP_CLIENT_ID>

# Run with LLM orchestration
python3 -m silent_updater.cli run \
    --repo-url "file:///path/to/repo" \
    --pipeline-cmd "mvn clean verify -DskipITs" \
    --compliance ./examples/compliance_config.json \
    --vuln-xlsx ./my_vulns.xlsx \
    --model gpt-4o
```

For corporate proxy (Basic auth):
```bash
export SILENT_UPDATER_PROXY="http://USER:PASS@user-proxy.host:port"
python3 -m silent_updater.cli login
```

For SPNEGO/Kerberos proxies (common in banks), see `docs/proxy.md` for setting up a local `px-proxy` bridge.

> **Important policy note**: GitHub Models is a separate product from GitHub Copilot. Sending repository contents to `models.github.ai` is NOT covered by your bank's Copilot DPA. Don't run this mode on corporate code without an explicit approval from InfoSec.

---

## Layout

```
src/silent_updater/
├── auth/                  # GitHub device-flow OAuth (LLM mode only)
├── llm/                   # GitHub Models client + generic tool-use loop
├── agent/
│   ├── base.py            # AIAgent ABC
│   ├── dependency_updater.py  # LLM-driven orchestrator
│   └── deterministic.py   # No-LLM Python orchestrator
├── tools/                 # maven_ops, git_ops, pipeline_ops, bitbucket_ops, pom_inspector
├── inputs/                # Excel + compliance JSON loaders
├── semver.py              # Maven-tolerant version parser + filters
├── models.py              # dataclasses
├── reporter.py            # update_report.md
└── cli.py
```

---

## Tests

```bash
python3 -m pytest -q
```

Coverage:

- Unit: Excel/compliance parsing, `dependency:tree` parser, XML editing strategies, OAuth device flow (HTTP mocked), Bitbucket PR client (HTTP mocked), tool-loop, reporter, git ops against a local bare repo, semver helpers.
- E2E (mocked Maven, real git): direct dep, transitive via BOM, transitive needing dm_override after a failed direct bump, retry on pipeline failure — for both the LLM and deterministic agents.

---

## Out of scope (for now)

- Gradle.
- Bitbucket Cloud (this targets on-prem Server / Data Center).
- Parallel try of multiple versions for the same dep.
- Automatic CVE enrichment from NVD.
