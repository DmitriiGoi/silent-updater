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
        # Caches populated once at run() start so we don't invoke Maven per vuln.
        self._tree: "maven_ops.TreeAnalysis | None" = None
        self._all_updates: dict[str, str] = {}

    def run(self) -> RunReport:
        started = dt.datetime.now().isoformat(timespec="seconds")
        branch_name = self.compliance.branch_template.format(
            date=dt.date.today().strftime("%Y%m%d"),
        )
        report = RunReport(repo_url=self.repo_url, started_at=started)
        log.info("starting deterministic update run; workdir=%s", self.workdir)
        log.info("loaded %d vulnerable entries; compliance strategy=%s, max_attempts=%d",
                 len(self.vuln_entries), self.compliance.update_strategy,
                 self.compliance.max_attempts_per_dep)

        if not self.dry_run:
            log.info("creating branch %s", branch_name)
            git_ops.create_branch(branch_name, cwd=self.workdir)
        else:
            log.info("dry-run: would create branch %s", branch_name)
        report.branch = branch_name

        root_pom = pom_inspector.find_root_pom(self.workdir)
        log.info("root pom: %s", root_pom.relative_to(self.workdir))

        # ── Upfront discovery: one mvn call each, then in-memory lookups ──
        log.info("[discovery 1/2] running full mvn dependency:tree once "
                 "(replaces N per-vuln calls)")
        self._tree = maven_ops.full_dependency_tree(self.workdir)
        log.info("[discovery 1/2] tree has %d artifact paths", len(self._tree.paths))

        log.info("[discovery 2/2] running mvn versions:display-dependency-updates "
                 "once (for declared deps; transitive vulns rely on Veracode hints)")
        self._all_updates = maven_ops.all_available_updates(self.workdir)
        log.info("[discovery 2/2] %d declared deps have available updates",
                 len(self._all_updates))

        sorted_entries = sorted(self.vuln_entries, key=lambda v: v.severity.rank)
        total = len(sorted_entries)
        for i, entry in enumerate(sorted_entries, 1):
            log.info("─── [%d/%d] %s (%s, vuln=%s, cve=%s) ───",
                     i, total, entry.ga, entry.severity.value,
                     entry.vuln_version, entry.cve or "no-cve")
            outcome = DepOutcome(entry=entry)
            report.outcomes.append(outcome)

            excepted, reason = self.compliance.is_excepted(entry.ga)
            if excepted:
                log.info("  SKIP: in exceptions (reason: %s)", reason)
                outcome.final_verdict = "skip"
                outcome.attempts.append(AttemptLog(
                    ga=entry.ga, from_version=entry.vuln_version, to_version="",
                    strategy=None, pipeline_exit=None,
                    stderr_excerpt="", verdict="skip",
                    note=f"in exceptions: {reason}",
                ))
                continue

            self._process_vuln(entry, root_pom, outcome)
            log.info("  outcome: %s%s",
                     outcome.final_verdict,
                     f" -> {outcome.final_version} via {outcome.final_strategy}"
                     if outcome.final_verdict == "success" else "")

        any_commits = any(o.final_verdict == "success" for o in report.outcomes)
        log.info("done: %d updated, %d gave up, %d skipped",
                 len(report.succeeded), len(report.gave_up), len(report.skipped))

        if any_commits and not self.dry_run:
            log.info("pushing branch %s", branch_name)
            try:
                git_ops.push_branch(branch_name, cwd=self.workdir)
            except git_ops.GitError as ex:
                log.warning("push failed: %s", ex)

            if self.bitbucket is not None:
                log.info("opening Bitbucket PR")
                try:
                    url = bitbucket_ops.create_pull_request(
                        self.bitbucket,
                        title=self._pr_title(report),
                        description=self._pr_description(report),
                        source_branch=branch_name,
                        target_branch=self.compliance.pr_target_branch,
                    )
                    report.pr_url = url
                    log.info("PR opened: %s", url)
                except bitbucket_ops.BitbucketError as ex:
                    log.warning("PR creation failed: %s", ex)

        report.finished_at = dt.datetime.now().isoformat(timespec="seconds")
        report_path = self.workdir / "update_report.md"
        write_report(report, report_path)
        log.info("report written: %s", report_path)
        return report

    # ---------------- per-dep processing ----------------

    def _process_vuln(self, entry: VulnEntry, root_pom: Path, outcome: DepOutcome) -> None:
        assert self._tree is not None
        paths_for = self._tree.paths_for(entry.ga)
        if not paths_for:
            log.info("  SKIP: %s not in dependency tree", entry.ga)
            outcome.final_verdict = "skip"
            outcome.attempts.append(AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version, to_version="",
                strategy=None, pipeline_exit=None, stderr_excerpt="",
                verdict="skip", note="GA not present in dependency tree",
            ))
            return

        is_direct = self._tree.is_direct(entry.ga)
        log.info("  found %d path(s) in tree; classification: %s",
                 len(paths_for), "direct" if is_direct else "transitive")
        if not is_direct:
            for p in paths_for[:3]:
                log.info("    via: %s", " -> ".join(n.ga for n in p.nodes))
        strategies: list[Strategy] = (
            ["bump_direct"] if is_direct
            else ["dm_override", "exclusion_and_direct"]
        )

        log.info("  picking candidate versions (from cache + Veracode hints)")
        candidates = self._pick_target_versions(entry)
        if not candidates:
            log.info("  GIVE UP: no candidate versions pass compliance filter "
                     "(strategy=%s, pin=%s, vuln=%s, fixed_hints=%s)",
                     self.compliance.update_strategy,
                     self.compliance.pin_for(entry.ga) or "(none)",
                     entry.vuln_version, list(entry.fixed_versions) or "(none)")
            outcome.final_verdict = "gave_up"
            outcome.attempts.append(AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version, to_version="",
                strategy=None, pipeline_exit=None, stderr_excerpt="",
                verdict="gave_up",
                note="no candidate versions pass compliance filter",
            ))
            return
        log.info("  %d candidate version(s): %s", len(candidates), candidates)
        log.info("  strategy chain: %s", strategies)

        budget = self.compliance.max_attempts_per_dep
        attempts_used = 0
        # Parent dep — only needed for exclusion_and_direct strategy
        parent_ga: str | None = None
        if not is_direct:
            if paths_for and paths_for[0].root_dep is not None:
                parent_ga = paths_for[0].root_dep.ga

        for strategy in strategies:
            if strategy == "exclusion_and_direct" and parent_ga is None:
                continue
            for target_version in candidates:
                if attempts_used >= budget:
                    log.info("  GIVE UP: max_attempts_per_dep (%d) exhausted", budget)
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
                log.info("  attempt %d/%d: %s -> %s",
                         attempts_used, budget, strategy, target_version)
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
            log.info("    applying %s on %s", strategy, applied_paths[0])
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

        log.info("    running pipeline: %s (timeout %ds)",
                 self.pipeline_cmd, self.pipeline_timeout)
        pipeline = pipeline_ops.run_pipeline(
            self.pipeline_cmd, cwd=self.workdir, timeout=self.pipeline_timeout,
        )
        log.info("    pipeline finished: exit=%d, %.1fs, log=%s",
                 pipeline.exit_code, pipeline.duration_seconds,
                 pipeline.full_log_path)
        if pipeline.exit_code != 0:
            log.info("    RETRY: pipeline failed; rolling back %s", applied_paths)
            self._rollback(applied_paths)
            return AttemptLog(
                ga=entry.ga, from_version=entry.vuln_version,
                to_version=target_version, strategy=strategy,
                pipeline_exit=pipeline.exit_code,
                stderr_excerpt=pipeline.stderr_tail[-500:],
                verdict="retry",
                note=f"pipeline failed (timed_out={pipeline.timed_out})",
            )

        log.info("    verifying vuln resolved via mvn dependency:tree")
        verify = maven_ops.verify_vuln_resolved(
            self.workdir, entry.ga, entry.vuln_version,
        )
        log.info("    verify result: resolved=%s, current=%s, note=%s",
                 verify.get("resolved"), verify.get("current_version"),
                 verify.get("note", ""))
        if not verify.get("resolved"):
            log.info("    RETRY: vuln still in tree; rolling back")
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
        log.info("    SUCCESS: commit %s", sha[:8])
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
        """Pick & order candidate target versions.

        Priority:
          1. Versions explicitly suggested by the vulnerability source
             (e.g. Veracode 'Fixed Version' column) — try these first since
             they're the verified fix.
          2. Newer versions reported by `mvn versions:display-dependency-updates`.

        All candidates are filtered by compliance (strictly greater than vuln,
        satisfies pins, passes update_strategy) and sorted smallest-bump-first.
        """
        pin = self.compliance.pin_for(entry.ga)
        strategy = self.compliance.update_strategy

        def passes_filters(v: str) -> bool:
            if not is_strictly_greater(v, entry.vuln_version):
                return False
            if not satisfies_pin(v, pin):
                return False
            if not allowed_by_strategy(entry.vuln_version, v, strategy):
                return False
            return True

        def sort_key(v: str) -> tuple:
            parsed = Version.parse(v)
            if parsed is None:
                return (9, 0, 0)
            return (parsed.major, parsed.minor, parsed.patch)

        # Sources, in priority order; dedupe preserving first-seen order.
        ordered: list[str] = []
        seen: set[str] = set()

        for v in entry.fixed_versions:
            if v not in seen and passes_filters(v):
                ordered.append(v)
                seen.add(v)

        # Cached display-dependency-updates result (single-version per GA from
        # versions-maven-plugin); only useful for direct deps. For transitive
        # deps the cache is typically empty for this GA and we rely on
        # entry.fixed_versions above.
        cached = self._all_updates.get(entry.ga)
        if cached and passes_filters(cached) and cached not in seen:
            ordered.append(cached)
            seen.add(cached)

        # Among Veracode hints, also sort by version size so we still try the
        # smallest acceptable bump first.
        from_hints = [v for v in ordered if v in entry.fixed_versions]
        from_cached = [v for v in ordered if v not in entry.fixed_versions]
        return sorted(from_hints, key=sort_key) + from_cached

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
