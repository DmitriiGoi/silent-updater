# silent-updater

LLM-driven autonomous agent for updating vulnerable Java/Maven dependencies in repositories hosted on **Bitbucket Server / Data Center**.

The agent reads a list of vulnerable libraries from Excel, clones the target repo, and iteratively figures out a safe target version for each vulnerability — trying direct bumps, BOM updates, `dependencyManagement` overrides, and exclusion strategies until the regression pipeline passes and the vulnerability is gone from `mvn dependency:tree`.

Most CVEs in real Java projects live in *transitive* dependencies — the agent is built around that fact.

## How it works

1. CLI clones the Bitbucket repo into an isolated working directory.
2. The agent authenticates to **GitHub Models API** (`models.github.ai`, OpenAI-compatible) using a GitHub OAuth device-flow token — the same UX as the IntelliJ Copilot plugin (a browser opens, you click "Authorize").
3. The LLM is given an inventory of tools (`dependency_tree`, `bump_direct_version`, `add_dependency_management_override`, `bump_bom_import`, `add_exclusion_and_direct`, `run_pipeline`, `verify_vuln_resolved`, git ops, Bitbucket PR ops, etc.) and a system prompt with the algorithm.
4. For each vulnerable dependency the LLM picks a strategy based on the dependency tree, applies it, runs the regression pipeline, verifies the vulnerable version is no longer in the tree, and either commits or rolls back and tries again. Hard cap on attempts per dep.
5. After all deps are processed, the agent pushes the branch and opens a Bitbucket PR.
6. An `update_report.md` is written into the workdir with everything that succeeded, failed, or was skipped.

## Inputs

### `vulnerable_libs.xlsx`

A spreadsheet with the columns:

| groupId | artifactId | vulnerableVersion | cve | severity | notes |
|---|---|---|---|---|---|
| org.apache.logging.log4j | log4j-core | 2.14.1 | CVE-2021-44228 | CRITICAL | log4shell |

Only `groupId`, `artifactId`, `vulnerableVersion` are required. The agent **discovers the safe target version by trial and error** — you do not specify it.

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

`update_strategy` is one of `patch`, `patch_minor`, or `any`.

## Install

```
python -m pip install -e .[dev]
```

You need: Python 3.11+, `mvn` on PATH, `git` on PATH.

## Usage

```
# One-time GitHub auth (opens browser)
silent-updater login --client-id <YOUR_GH_OAUTH_APP_CLIENT_ID>

# Store Bitbucket Personal Access Token (HTTP Access Token)
silent-updater set-bitbucket-token <PAT>

# Run an update against a repo
silent-updater run \
    --repo-url ssh://git@bitbucket.example.com/proj/app.git \
    --pipeline-cmd "mvn clean verify -DskipITs" \
    --compliance ./examples/compliance_config.json \
    --vuln-xlsx ./examples/vulnerable_libs.xlsx \
    --bitbucket-base https://bitbucket.example.com \
    --project-key PROJ --repo-slug app \
    --model gpt-4o
```

Add `--dry-run` to plan only — the LLM still runs but tools return "would do X" rather than executing.

Set `SILENT_UPDATER_GH_CLIENT_ID` in your environment to avoid passing `--client-id` every time.

## Layout

```
src/silent_updater/
├── auth/                  # GitHub device-flow OAuth
├── llm/                   # GitHub Models client + generic tool-use loop
├── agent/                 # AIAgent base + DependencyUpdaterAgent + system prompt
├── tools/                 # maven_ops, git_ops, pipeline_ops, bitbucket_ops, pom_inspector
├── inputs/                # Excel + compliance JSON loaders
├── models.py              # dataclasses
├── reporter.py            # update_report.md
└── cli.py
```

## Tests

```
python -m pytest
```

Unit tests cover Excel/compliance parsing, `dependency:tree` parsing, XML editing strategies (`add_dependency_management_override`, `bump_bom_import`, `add_exclusion_and_direct`), the OAuth device flow (HTTP mocked), the Bitbucket PR client (HTTP mocked), the generic tool-use loop, the reporter, and git operations (against a real local bare repo).

E2E tests drive the agent end-to-end with a scripted FakeLLM and a real local git repo + mocked Maven layer:

- `test_agent_direct_dep.py` — direct dependency bump.
- `test_agent_transitive_via_bom.py` — vulnerable dep brought in by a BOM import; strategy is `bump_bom_import`.
- `test_agent_transitive_dm_override.py` — multiple paths to the vulnerability; first `bump_direct_version` doesn't displace it; agent falls back to `add_dependency_management_override`.
- `test_agent_retry_on_failure.py` — first version choice breaks the build; agent reads stderr and tries a smaller bump.

## Out of scope (for now)

- Gradle.
- Bitbucket Cloud (this targets on-prem Server / Data Center).
- Parallel try of multiple versions for the same dep.
- Automatic CVE enrichment from NVD.
