from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.llm.tool_loop import ToolDispatcher
from silent_updater.models import (
    AttemptLog,
    DepOutcome,
    RunReport,
    Severity,
    Strategy,
    VulnEntry,
)
from silent_updater.reporter import write_report
from silent_updater.tools import (
    bitbucket_ops,
    git_ops,
    maven_ops,
    pipeline_ops,
    pom_inspector,
)
from silent_updater.tools.bitbucket_ops import BitbucketCoords


# ---------------------------------------------------------------------------
# Runtime state — what the dispatcher closes over for the duration of one run.
# ---------------------------------------------------------------------------


@dataclass
class AgentRuntime:
    workdir: Path
    pipeline_cmd: str
    pipeline_timeout: int
    vuln_entries: list[VulnEntry]
    compliance: ComplianceConfig
    bitbucket: BitbucketCoords | None
    branch_name: str
    report: RunReport
    dry_run: bool = False
    outcomes_by_ga: dict[str, DepOutcome] = field(default_factory=dict)
    changed_pom_paths: set[str] = field(default_factory=set)

    def outcome_for(self, ga: str) -> DepOutcome:
        if ga in self.outcomes_by_ga:
            return self.outcomes_by_ga[ga]
        entry = next((v for v in self.vuln_entries if v.ga == ga), None)
        if entry is None:
            entry = VulnEntry(
                group_id=ga.split(":", 1)[0],
                artifact_id=ga.split(":", 1)[1] if ":" in ga else ga,
                vuln_version="?",
                cve="",
                severity=Severity.UNKNOWN,
            )
        outcome = DepOutcome(entry=entry)
        self.outcomes_by_ga[ga] = outcome
        self.report.outcomes.append(outcome)
        return outcome


# ---------------------------------------------------------------------------
# Tool schemas (OpenAI-compatible function-call definitions)
# ---------------------------------------------------------------------------


def _fn(name: str, description: str, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": params},
    }


def tool_schemas() -> list[dict[str, Any]]:
    str_p = {"type": "string"}
    return [
        _fn("list_vulnerable_deps",
            "Return the parsed list of vulnerable dependencies from the Excel input.",
            {"type": "object", "properties": {}, "additionalProperties": False}),
        _fn("get_compliance",
            "Return the compliance config (update_strategy, exceptions, pins, max_attempts).",
            {"type": "object", "properties": {}, "additionalProperties": False}),
        _fn("list_direct_dependencies",
            "List direct <dependencies> in a pom.xml. Defaults to root pom.",
            {"type": "object", "properties": {"pom_path": str_p}}),
        _fn("dependency_tree",
            "Run `mvn dependency:tree`. If ga is provided, scopes to that artifact's ancestry.",
            {"type": "object",
             "properties": {"ga": str_p},
             "required": []}),
        _fn("effective_version",
            "Resolve the current effective version of a GA (after BOM/parent resolution).",
            {"type": "object",
             "properties": {"ga": str_p},
             "required": ["ga"]}),
        _fn("list_available_versions",
            "List available versions of a GA newer than the current effective.",
            {"type": "object",
             "properties": {"ga": str_p},
             "required": ["ga"]}),
        _fn("probe_version_exists",
            "Probe whether a specific GAV resolves from configured Maven repos.",
            {"type": "object",
             "properties": {"ga": str_p, "version": str_p},
             "required": ["ga", "version"]}),
        _fn("bump_direct_version",
            "Strategy: bump version of a DIRECT dependency.",
            {"type": "object",
             "properties": {"ga": str_p, "version": str_p},
             "required": ["ga", "version"]}),
        _fn("bump_managed_version",
            "Strategy: bump an existing <dependencyManagement> entry's version.",
            {"type": "object",
             "properties": {"ga": str_p, "version": str_p},
             "required": ["ga", "version"]}),
        _fn("bump_parent_version",
            "Strategy: bump <parent>/<version> (e.g. spring-boot-starter-parent).",
            {"type": "object",
             "properties": {"ga": str_p, "version": str_p},
             "required": ["ga", "version"]}),
        _fn("add_dependency_management_override",
            "Strategy: add/update <dependencyManagement>/<dependencies>/<dependency> "
            "to pin a safe version. Default workhorse for transitive vulns.",
            {"type": "object",
             "properties": {"ga": str_p, "version": str_p, "pom_path": str_p},
             "required": ["ga", "version"]}),
        _fn("add_exclusion_and_direct",
            "Strategy: add <exclusion> to parent dep + add direct dep with safe version.",
            {"type": "object",
             "properties": {"parent_ga": str_p, "vuln_ga": str_p,
                            "version": str_p, "pom_path": str_p},
             "required": ["parent_ga", "vuln_ga", "version"]}),
        _fn("bump_bom_import",
            "Strategy: update version of an existing BOM import (<scope>import</scope>).",
            {"type": "object",
             "properties": {"bom_ga": str_p, "version": str_p, "pom_path": str_p},
             "required": ["bom_ga", "version"]}),
        _fn("run_pipeline",
            "Run the regression pipeline command. Returns exit_code + stderr/stdout tails.",
            {"type": "object", "properties": {}, "additionalProperties": False}),
        _fn("verify_vuln_resolved",
            "Re-run dependency:tree and check that the vulnerable version no longer appears.",
            {"type": "object",
             "properties": {"ga": str_p, "vuln_version": str_p},
             "required": ["ga", "vuln_version"]}),
        _fn("git_status",
            "Run `git status --porcelain`.",
            {"type": "object", "properties": {}, "additionalProperties": False}),
        _fn("git_commit",
            "Stage the listed paths and commit. Returns commit sha.",
            {"type": "object",
             "properties": {
                 "paths": {"type": "array", "items": str_p},
                 "message": str_p,
             },
             "required": ["paths", "message"]}),
        _fn("git_checkout_file",
            "Rollback file(s) to HEAD (safe `git checkout HEAD -- <path>`).",
            {"type": "object",
             "properties": {"paths": {"type": "array", "items": str_p}},
             "required": ["paths"]}),
        _fn("create_branch",
            "Create + checkout a new branch from current HEAD.",
            {"type": "object", "properties": {"name": str_p}, "required": ["name"]}),
        _fn("push_branch",
            "Push the current branch with -u to origin.",
            {"type": "object", "properties": {}, "additionalProperties": False}),
        _fn("create_bitbucket_pr",
            "Open a Pull Request on Bitbucket Server. Returns PR URL.",
            {"type": "object",
             "properties": {"title": str_p, "description": str_p},
             "required": ["title", "description"]}),
        _fn("record_outcome",
            "Record an attempt for a dep. verdict: success|retry|gave_up|skip.",
            {"type": "object",
             "properties": {
                 "ga": str_p,
                 "from_version": str_p,
                 "to_version": str_p,
                 "strategy": str_p,
                 "verdict": {"type": "string",
                             "enum": ["success", "retry", "gave_up", "skip"]},
                 "note": str_p,
             },
             "required": ["ga", "verdict"]}),
        _fn("write_report",
            "Write the final update_report.md to disk. Call at the very end.",
            {"type": "object", "properties": {}, "additionalProperties": False}),
    ]


# ---------------------------------------------------------------------------
# Dispatcher: maps tool names → handler functions bound to runtime.
# ---------------------------------------------------------------------------


def build_dispatcher(rt: AgentRuntime) -> ToolDispatcher:
    handlers = {
        "list_vulnerable_deps": lambda a: _list_vulns(rt),
        "get_compliance": lambda a: _compliance(rt),
        "list_direct_dependencies": lambda a: _list_direct(rt, a),
        "dependency_tree": lambda a: _tree(rt, a),
        "effective_version": lambda a: _effective(rt, a),
        "list_available_versions": lambda a: _available(rt, a),
        "probe_version_exists": lambda a: _probe(rt, a),
        "bump_direct_version": lambda a: _bump_direct(rt, a),
        "bump_managed_version": lambda a: _bump_managed(rt, a),
        "bump_parent_version": lambda a: _bump_parent(rt, a),
        "add_dependency_management_override": lambda a: _dm_override(rt, a),
        "add_exclusion_and_direct": lambda a: _excl_and_direct(rt, a),
        "bump_bom_import": lambda a: _bom_import(rt, a),
        "run_pipeline": lambda a: _run_pipeline(rt),
        "verify_vuln_resolved": lambda a: _verify(rt, a),
        "git_status": lambda a: _git_status(rt),
        "git_commit": lambda a: _git_commit(rt, a),
        "git_checkout_file": lambda a: _git_checkout(rt, a),
        "create_branch": lambda a: _create_branch(rt, a),
        "push_branch": lambda a: _push_branch(rt),
        "create_bitbucket_pr": lambda a: _create_pr(rt, a),
        "record_outcome": lambda a: _record_outcome(rt, a),
        "write_report": lambda a: _write_report(rt),
    }
    return ToolDispatcher(handlers=handlers, schemas=tool_schemas())


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _list_vulns(rt: AgentRuntime) -> dict:
    return {
        "vulnerabilities": [
            {
                "ga": v.ga,
                "groupId": v.group_id,
                "artifactId": v.artifact_id,
                "vulnerableVersion": v.vuln_version,
                "cve": v.cve,
                "severity": v.severity.value,
                "notes": v.notes,
            }
            for v in sorted(rt.vuln_entries, key=lambda x: x.severity.rank)
        ]
    }


def _compliance(rt: AgentRuntime) -> dict:
    return json.loads(rt.compliance.model_dump_json())


def _resolve_pom_path(rt: AgentRuntime, arg_path: str | None) -> Path:
    if arg_path:
        candidate = (rt.workdir / arg_path).resolve()
        _ensure_inside_workdir(rt, candidate)
        return candidate
    return pom_inspector.find_root_pom(rt.workdir)


def _ensure_inside_workdir(rt: AgentRuntime, p: Path) -> None:
    try:
        p.resolve().relative_to(rt.workdir.resolve())
    except ValueError:
        raise ValueError(f"path {p} is outside workdir {rt.workdir}")


def _list_direct(rt: AgentRuntime, args: dict) -> dict:
    pom = _resolve_pom_path(rt, args.get("pom_path"))
    deps = pom_inspector.list_direct_dependencies(pom)
    return {
        "pom": str(pom.relative_to(rt.workdir)),
        "dependencies": [
            {
                "ga": d.ga, "version": d.version,
                "scope": d.scope, "type": d.type,
            } for d in deps
        ],
    }


def _tree(rt: AgentRuntime, args: dict) -> dict:
    ga = args.get("ga")
    analysis = maven_ops.dependency_tree(rt.workdir, ga=ga or None)
    paths = []
    for p in analysis.paths:
        if ga and p.leaf.ga != ga:
            continue
        paths.append({
            "leaf": {
                "ga": p.leaf.ga, "version": p.leaf.version,
                "scope": p.leaf.scope, "depth": p.leaf.depth,
            },
            "chain": [f"{n.ga}:{n.version}" for n in p.nodes],
        })
    return {"paths": paths, "count": len(paths)}


def _effective(rt: AgentRuntime, args: dict) -> dict:
    ver = maven_ops.effective_version(rt.workdir, args["ga"])
    return {"ga": args["ga"], "effective_version": ver}


def _available(rt: AgentRuntime, args: dict) -> dict:
    versions = maven_ops.list_available_versions(rt.workdir, args["ga"])
    return {"ga": args["ga"], "versions": versions}


def _probe(rt: AgentRuntime, args: dict) -> dict:
    exists = maven_ops.probe_version_exists(rt.workdir, args["ga"], args["version"])
    return {"ga": args["ga"], "version": args["version"], "exists": exists}


def _mark_changed(rt: AgentRuntime, pom: Path) -> None:
    rt.changed_pom_paths.add(str(pom.relative_to(rt.workdir)).replace("\\", "/"))


def _bump_direct(rt: AgentRuntime, args: dict) -> dict:
    if rt.dry_run:
        return {"dry_run": True, "would_apply": "bump_direct_version", **args}
    maven_ops.bump_direct_version(rt.workdir, args["ga"], args["version"])
    _mark_changed(rt, pom_inspector.find_root_pom(rt.workdir))
    return {"applied": "bump_direct_version", **args}


def _bump_managed(rt: AgentRuntime, args: dict) -> dict:
    if rt.dry_run:
        return {"dry_run": True, "would_apply": "bump_managed_version", **args}
    maven_ops.bump_managed_version(rt.workdir, args["ga"], args["version"])
    _mark_changed(rt, pom_inspector.find_root_pom(rt.workdir))
    return {"applied": "bump_managed_version", **args}


def _bump_parent(rt: AgentRuntime, args: dict) -> dict:
    if rt.dry_run:
        return {"dry_run": True, "would_apply": "bump_parent_version", **args}
    maven_ops.bump_parent_version(rt.workdir, args["ga"], args["version"])
    _mark_changed(rt, pom_inspector.find_root_pom(rt.workdir))
    return {"applied": "bump_parent_version", **args}


def _dm_override(rt: AgentRuntime, args: dict) -> dict:
    pom = _resolve_pom_path(rt, args.get("pom_path"))
    if rt.dry_run:
        return {"dry_run": True, "would_apply": "add_dependency_management_override",
                "pom": str(pom), **{k: v for k, v in args.items() if k != "pom_path"}}
    maven_ops.add_dependency_management_override(pom, args["ga"], args["version"])
    _mark_changed(rt, pom)
    return {"applied": "add_dependency_management_override",
            "pom": str(pom.relative_to(rt.workdir)),
            "ga": args["ga"], "version": args["version"]}


def _excl_and_direct(rt: AgentRuntime, args: dict) -> dict:
    pom = _resolve_pom_path(rt, args.get("pom_path"))
    if rt.dry_run:
        return {"dry_run": True, "would_apply": "add_exclusion_and_direct", **args}
    maven_ops.add_exclusion_and_direct(
        pom, args["parent_ga"], args["vuln_ga"], args["version"]
    )
    _mark_changed(rt, pom)
    return {"applied": "add_exclusion_and_direct",
            "pom": str(pom.relative_to(rt.workdir)),
            "parent_ga": args["parent_ga"],
            "vuln_ga": args["vuln_ga"],
            "version": args["version"]}


def _bom_import(rt: AgentRuntime, args: dict) -> dict:
    pom = _resolve_pom_path(rt, args.get("pom_path"))
    if rt.dry_run:
        return {"dry_run": True, "would_apply": "bump_bom_import", **args}
    maven_ops.bump_bom_import(pom, args["bom_ga"], args["version"])
    _mark_changed(rt, pom)
    return {"applied": "bump_bom_import",
            "pom": str(pom.relative_to(rt.workdir)),
            "bom_ga": args["bom_ga"], "version": args["version"]}


def _run_pipeline(rt: AgentRuntime) -> dict:
    if rt.dry_run:
        return {"dry_run": True, "exit_code": 0, "stderr_tail": "", "stdout_tail": ""}
    result = pipeline_ops.run_pipeline(
        rt.pipeline_cmd, cwd=rt.workdir, timeout=rt.pipeline_timeout
    )
    return {
        "exit_code": result.exit_code,
        "stdout_tail": result.stdout_tail,
        "stderr_tail": result.stderr_tail,
        "timed_out": result.timed_out,
        "duration_seconds": result.duration_seconds,
        "full_log_path": result.full_log_path,
    }


def _verify(rt: AgentRuntime, args: dict) -> dict:
    return maven_ops.verify_vuln_resolved(rt.workdir, args["ga"], args["vuln_version"])


def _git_status(rt: AgentRuntime) -> dict:
    return {"porcelain": git_ops.status_porcelain(rt.workdir)}


def _git_commit(rt: AgentRuntime, args: dict) -> dict:
    paths = [str(p) for p in args["paths"]]
    if rt.dry_run:
        return {"dry_run": True, "would_commit": paths, "message": args["message"]}
    git_ops.add(paths, cwd=rt.workdir)
    sha = git_ops.commit(args["message"], cwd=rt.workdir)
    rt.changed_pom_paths.difference_update(paths)
    return {"committed": True, "sha": sha, "paths": paths}


def _git_checkout(rt: AgentRuntime, args: dict) -> dict:
    paths = [str(p) for p in args["paths"]]
    if rt.dry_run:
        return {"dry_run": True, "would_checkout": paths}
    git_ops.checkout_files(paths, cwd=rt.workdir)
    rt.changed_pom_paths.difference_update(paths)
    return {"checked_out": paths}


def _create_branch(rt: AgentRuntime, args: dict) -> dict:
    if rt.dry_run:
        return {"dry_run": True, "would_create_branch": args["name"]}
    git_ops.create_branch(args["name"], cwd=rt.workdir)
    rt.branch_name = args["name"]
    rt.report.branch = args["name"]
    return {"branch": args["name"]}


def _push_branch(rt: AgentRuntime) -> dict:
    if rt.dry_run:
        return {"dry_run": True, "would_push": rt.branch_name}
    git_ops.push_branch(rt.branch_name, cwd=rt.workdir)
    return {"pushed": rt.branch_name}


def _create_pr(rt: AgentRuntime, args: dict) -> dict:
    if rt.bitbucket is None:
        return {"error": "Bitbucket coordinates not configured"}
    if rt.dry_run:
        return {"dry_run": True, "would_create_pr": args}
    url = bitbucket_ops.create_pull_request(
        rt.bitbucket,
        title=args["title"],
        description=args["description"],
        source_branch=rt.branch_name,
        target_branch=rt.compliance.pr_target_branch,
    )
    rt.report.pr_url = url
    return {"pr_url": url}


def _record_outcome(rt: AgentRuntime, args: dict) -> dict:
    ga = args["ga"]
    outcome = rt.outcome_for(ga)
    strategy_val: Strategy | None = args.get("strategy") or None  # type: ignore[assignment]
    attempt = AttemptLog(
        ga=ga,
        from_version=args.get("from_version", ""),
        to_version=args.get("to_version", ""),
        strategy=strategy_val,
        pipeline_exit=None,
        stderr_excerpt="",
        verdict=args["verdict"],
        note=args.get("note", ""),
    )
    outcome.attempts.append(attempt)
    outcome.final_verdict = args["verdict"]
    if args["verdict"] == "success":
        outcome.final_version = attempt.to_version
        outcome.final_strategy = strategy_val
    return {"recorded": True, "ga": ga, "verdict": args["verdict"]}


def _write_report(rt: AgentRuntime) -> dict:
    path = rt.workdir / "update_report.md"
    write_report(rt.report, path)
    return {"report_path": str(path)}
