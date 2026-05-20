from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from silent_updater.agent.base import AIAgent
from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.models import (
    AttemptLog,
    DepOutcome,
    RunReport,
    Strategy,
    VulnEntry,
)
from silent_updater.reporter import write_report
from silent_updater.semver import (
    Version,
    allowed_by_strategy,
    is_strictly_greater,
    satisfies_pin,
)
from silent_updater.tools import (
    bitbucket_ops,
    git_ops,
    maven_ops,
    pipeline_ops,
    pom_inspector,
)
from silent_updater.tools.bitbucket_ops import BitbucketCoords


log = logging.getLogger(__name__)


class DeterministicUpdaterAgent(AIAgent):
    """No-LLM updater. Algorithm is hard-coded in Python.

    For each vuln (sorted by severity):
      - skip if in compliance.exceptions
      - check dependency_tree → if GA absent, skip
      - decide strategy chain:
          direct dep    → [bump_direct]
          transitive    → [dm_override, exclusion_and_direct]
      - filter candidate versions by: strictly greater than vuln, satisfies pin,
        passes update_strategy
      - try smallest acceptable bump first, then larger
      - per attempt: apply → run_pipeline → verify_vuln_resolved
        * success: commit + record
        * fail: rollback + record + try next
      - budget: compliance.max_attempts_per_dep
    """

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
        dry_run: bool = False,
    ):
        super().__init__(workdir)
        self.repo_url = repo_url
        self.pipeline_cmd = pipeline_cmd
        self.pipeline_timeout = pipeline_timeout
        self.vuln_entries = vuln_entries
        self.compliance = compliance
        self.bitbucket = bitbucket
        self.dry_run = dry_run

    def run(self) -> RunReport:
        started = dt.datetime.now().isoformat(timespec="seconds")
        branch_name = self.compliance.branch_template.format(
            date=dt.date.today().strftime("%Y%m%d"),
        )
        report = RunReport(repo_url=self.repo_url, started_at=started)

        if not self.dry_run:
            git_ops.create_branch(branch_name, cwd=self.workdir)
        report.branch = branch_name

        root_pom = pom_inspector.find_root_pom(self.workdir)

        for entry in sorted(self.vuln_entries, key=lambda v: v.severity.rank):
            outcome = DepOutcome(entry=entry)
            report.outcomes.append(outcome)

            excepted, reason = self.compliance.is_excepted(entry.ga)
            if excepted:
                outcome.final_verdict = "skip"
                outcome.attempts.append(AttemptLog(
                    ga=entry.ga, from_version=entry.vuln_version, to_version="",
                    strategy=None, pipeline_exit=None,
                    stderr_excerpt="", verdict="skip",
                    note=f"in exceptions: {reason}",
                ))
                continue

            self._process_vuln(entry, root_pom, outcome)

        any_commits = any(o.final_verdict == "success" for o in report.outcomes)
        if any_commits and not self.dry_run:
            try:
                git_ops.push_branch(branch_name, cwd=self.workdir)
            except git_ops.GitError as ex:
                log.warning("push failed: %s", ex)

            if self.bitbucket is not None:
                try:
                    url = bitbucket_ops.create_pull_request(
                        self.bitbucket,
                        title=self._pr_title(report),
                        description=self._pr_description(report),
                        source_branch=branch_name,
                        target_branch=self.compliance.pr_target_branch,
                    )
                    report.pr_url = url
                except bitbucket_ops.BitbucketError as ex:
                    log.warning("PR creation failed: %s", ex)

        report.finished_at = dt.datetime.now().isoformat(timespec="seconds")
        write_report(report, self.workdir / "update_report.md")
        return report

    # ---------------- per-dep processing ----------------

    def _process_vuln(self, entry: VulnEntry, root_pom: Path, outcome: DepOutcome) -> None:
        tree = maven_ops.dependency_tree(self.workdir, ga=entry.ga)
        if not tree.paths_for(entry.ga):
            outcome.final_verdict = "skip"
            outcome.attempts.append(AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version, to_version="",
                strategy=None, pipeline_exit=None, stderr_excerpt="",
                verdict="skip", note="GA not present in dependency tree",
            ))
            return

        is_direct = tree.is_direct(entry.ga)
        strategies: list[Strategy] = (
            ["bump_direct"] if is_direct
            else ["dm_override", "exclusion_and_direct"]
        )

        candidates = self._pick_target_versions(entry)
        if not candidates:
            outcome.final_verdict = "gave_up"
            outcome.attempts.append(AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version, to_version="",
                strategy=None, pipeline_exit=None, stderr_excerpt="",
                verdict="gave_up",
                note="no candidate versions pass compliance filter",
            ))
            return

        budget = self.compliance.max_attempts_per_dep
        attempts_used = 0
        # Parent dep — only needed for exclusion_and_direct strategy
        parent_ga: str | None = None
        if not is_direct:
            paths = tree.paths_for(entry.ga)
            if paths and paths[0].root_dep is not None:
                parent_ga = paths[0].root_dep.ga

        for strategy in strategies:
            if strategy == "exclusion_and_direct" and parent_ga is None:
                continue
            for target_version in candidates:
                if attempts_used >= budget:
                    outcome.final_verdict = "gave_up"
                    outcome.attempts.append(AttemptLog(
                        ga=entry.ga, from_version=entry.vuln_version,
                        to_version="", strategy=strategy,
                        pipeline_exit=None, stderr_excerpt="",
                        verdict="gave_up",
                        note=f"max_attempts_per_dep ({budget}) exhausted",
                    ))
                    return

                attempts_used += 1
                attempt = self._try_apply(
                    entry, root_pom, strategy, target_version, parent_ga,
                )
                outcome.attempts.append(attempt)
                if attempt.verdict == "success":
                    outcome.final_verdict = "success"
                    outcome.final_version = target_version
                    outcome.final_strategy = strategy
                    return
            # all versions exhausted for this strategy → next strategy

        outcome.final_verdict = "gave_up"

    def _try_apply(
        self,
        entry: VulnEntry,
        root_pom: Path,
        strategy: Strategy,
        target_version: str,
        parent_ga: str | None,
    ) -> AttemptLog:
        if self.dry_run:
            return AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version,
                to_version=target_version, strategy=strategy,
                pipeline_exit=0, stderr_excerpt="",
                verdict="success", note="dry-run",
            )

        applied_paths = [str(root_pom.relative_to(self.workdir)).replace("\\", "/")]
        try:
            if strategy == "bump_direct":
                maven_ops.bump_direct_version(self.workdir, entry.ga, target_version)
            elif strategy == "dm_override":
                maven_ops.add_dependency_management_override(
                    root_pom, entry.ga, target_version,
                )
            elif strategy == "exclusion_and_direct":
                assert parent_ga is not None
                maven_ops.add_exclusion_and_direct(
                    root_pom, parent_ga, entry.ga, target_version,
                )
            else:
                return AttemptLog(
                    ga=entry.ga, from_version=entry.vuln_version,
                    to_version=target_version, strategy=strategy,
                    pipeline_exit=None, stderr_excerpt="",
                    verdict="retry", note=f"unsupported strategy {strategy}",
                )
        except Exception as ex:
            log.warning("apply %s failed: %s", strategy, ex)
            self._rollback(applied_paths)
            return AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version,
                to_version=target_version, strategy=strategy,
                pipeline_exit=None, stderr_excerpt=str(ex)[:500],
                verdict="retry", note=f"apply error: {type(ex).__name__}",
            )

        pipeline = pipeline_ops.run_pipeline(
            self.pipeline_cmd, cwd=self.workdir, timeout=self.pipeline_timeout,
        )
        if pipeline.exit_code != 0:
            self._rollback(applied_paths)
            return AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version,
                to_version=target_version, strategy=strategy,
                pipeline_exit=pipeline.exit_code,
                stderr_excerpt=pipeline.stderr_tail[-500:],
                verdict="retry",
                note=f"pipeline failed (timed_out={pipeline.timed_out})",
            )

        verify = maven_ops.verify_vuln_resolved(
            self.workdir, entry.ga, entry.vuln_version,
        )
        if not verify.get("resolved"):
            self._rollback(applied_paths)
            return AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version,
                to_version=target_version, strategy=strategy,
                pipeline_exit=pipeline.exit_code, stderr_excerpt="",
                verdict="retry",
                note=f"vuln still in tree: {verify.get('note', '')}",
            )

        message = self._commit_message(entry, target_version, strategy)
        git_ops.add(applied_paths, cwd=self.workdir)
        sha = git_ops.commit(message, cwd=self.workdir)
        return AttemptLog(
            ga=entry.ga, from_version=entry.vuln_version,
            to_version=target_version, strategy=strategy,
            pipeline_exit=0, stderr_excerpt="",
            verdict="success", note=f"commit {sha[:8]}",
        )

    def _rollback(self, paths: list[str]) -> None:
        try:
            git_ops.checkout_files(paths, cwd=self.workdir)
        except git_ops.GitError:
            log.exception("rollback failed for %s", paths)

    def _pick_target_versions(self, entry: VulnEntry) -> list[str]:
        available = maven_ops.list_available_versions(self.workdir, entry.ga)
        if not available:
            return []

        pin = self.compliance.pin_for(entry.ga)
        strategy = self.compliance.update_strategy

        filtered: list[str] = []
        for v in available:
            if not is_strictly_greater(v, entry.vuln_version):
                continue
            if not satisfies_pin(v, pin):
                continue
            if not allowed_by_strategy(entry.vuln_version, v, strategy):
                continue
            filtered.append(v)

        def sort_key(v: str) -> tuple:
            parsed = Version.parse(v)
            if parsed is None:
                return (9, 0, 0)
            return (parsed.major, parsed.minor, parsed.patch)

        return sorted(filtered, key=sort_key)

    def _commit_message(self, entry: VulnEntry, to_version: str, strategy: Strategy) -> str:
        cve = entry.cve or "no-cve"
        return (
            f"fix(deps): bump {entry.ga} from {entry.vuln_version} to {to_version} "
            f"via {strategy} [{cve}]"
        )

    def _pr_title(self, report: RunReport) -> str:
        return f"Auto-update vulnerable dependencies ({len(report.succeeded)})"

    def _pr_description(self, report: RunReport) -> str:
        lines = ["Updated by silent-updater (deterministic mode):", ""]
        for o in report.succeeded:
            lines.append(
                f"- `{o.entry.ga}` {o.entry.vuln_version} -> {o.final_version} "
                f"via `{o.final_strategy}` ({o.entry.cve or 'no-cve'})"
            )
        if report.gave_up:
            lines.append("")
            lines.append("Could not update:")
            for o in report.gave_up:
                lines.append(f"- `{o.entry.ga}` ({o.entry.cve or 'no-cve'})")
        return "\n".join(lines)
