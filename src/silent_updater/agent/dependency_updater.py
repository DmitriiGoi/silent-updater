from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from silent_updater.agent.base import AIAgent
from silent_updater.agent.system_prompt import SYSTEM_PROMPT
from silent_updater.agent.tools import AgentRuntime, build_dispatcher
from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.llm.github_models_client import ChatClient
from silent_updater.llm.tool_loop import run_tool_loop
from silent_updater.models import RunReport, VulnEntry
from silent_updater.tools.bitbucket_ops import BitbucketCoords


class DependencyUpdaterAgent(AIAgent):
    def __init__(
        self,
        *,
        workdir: Path,
        repo_url: str,
        pipeline_cmd: str,
        pipeline_timeout: int,
        vuln_entries: list[VulnEntry],
        compliance: ComplianceConfig,
        bitbucket: BitbucketCoords | None,
        llm_client: ChatClient,
        model: str,
        max_iterations: int = 100,
        wall_clock_seconds: float | None = 7200.0,
        dry_run: bool = False,
        transcript_log: Path | None = None,
    ):
        super().__init__(workdir)
        self.repo_url = repo_url
        self.pipeline_cmd = pipeline_cmd
        self.pipeline_timeout = pipeline_timeout
        self.vuln_entries = vuln_entries
        self.compliance = compliance
        self.bitbucket = bitbucket
        self.llm_client = llm_client
        self.model = model
        self.max_iterations = max_iterations
        self.wall_clock_seconds = wall_clock_seconds
        self.dry_run = dry_run
        self.transcript_log = transcript_log

    def run(self) -> RunReport:
        started = dt.datetime.now().isoformat(timespec="seconds")
        branch_name = self.compliance.branch_template.format(
            date=dt.date.today().strftime("%Y%m%d"),
        )
        report = RunReport(repo_url=self.repo_url, started_at=started, branch=None)
        runtime = AgentRuntime(
            workdir=self.workdir,
            pipeline_cmd=self.pipeline_cmd,
            pipeline_timeout=self.pipeline_timeout,
            vuln_entries=self.vuln_entries,
            compliance=self.compliance,
            bitbucket=self.bitbucket,
            branch_name=branch_name,
            report=report,
            dry_run=self.dry_run,
        )
        dispatcher = build_dispatcher(runtime)
        initial = _build_initial_message(self.repo_url, self.pipeline_cmd, branch_name,
                                         self.vuln_entries, self.compliance,
                                         self.bitbucket is not None)
        run_tool_loop(
            client=self.llm_client,
            system_prompt=SYSTEM_PROMPT,
            initial_user_message=initial,
            dispatcher=dispatcher,
            max_iterations=self.max_iterations,
            wall_clock_seconds=self.wall_clock_seconds,
            transcript_log=self.transcript_log,
        )
        report.finished_at = dt.datetime.now().isoformat(timespec="seconds")
        return report


def _build_initial_message(
    repo_url: str,
    pipeline_cmd: str,
    branch_name: str,
    vulns: list[VulnEntry],
    compliance: ComplianceConfig,
    has_bitbucket: bool,
) -> str:
    vuln_summary = "\n".join(
        f"  - {v.ga} vulnerable@{v.vuln_version} ({v.severity.value}, {v.cve or 'no-cve'})"
        for v in sorted(vulns, key=lambda x: x.severity.rank)
    )
    pr_clause = (
        "After successful commits, push branch and call create_bitbucket_pr."
        if has_bitbucket
        else "Bitbucket coordinates are NOT configured — just push the branch, "
             "skip create_bitbucket_pr."
    )
    return (
        f"Repo (already cloned): {repo_url}\n"
        f"Working branch to use: {branch_name}\n"
        f"Regression pipeline command: {pipeline_cmd}\n\n"
        f"Vulnerable dependencies to update:\n{vuln_summary}\n\n"
        f"Compliance config:\n{json.dumps(json.loads(compliance.model_dump_json()), indent=2)}\n\n"
        f"Start by creating the branch '{branch_name}', then process each vulnerability.\n"
        f"{pr_clause}\n"
        f"Always finish with write_report."
    )
