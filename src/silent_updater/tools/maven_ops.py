from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

from silent_updater.tools.pom_inspector import _qname, parse_pom


MVN_TIMEOUT = 600


class MavenError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"mvn {' '.join(cmd)} -> exit {returncode}\n"
            f"--- stdout tail ---\n{stdout[-1500:]}\n"
            f"--- stderr tail ---\n{stderr[-1500:]}"
        )


@dataclass(frozen=True)
class TreeNode:
    group_id: str
    artifact_id: str
    type: str
    version: str
    scope: str
    depth: int

    @property
    def ga(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


@dataclass(frozen=True)
class TreePath:
    """Path from root project to one transitive node."""
    nodes: tuple[TreeNode, ...]

    @property
    def leaf(self) -> TreeNode:
        return self.nodes[-1]

    @property
    def root_dep(self) -> TreeNode | None:
        """The DIRECT dependency (depth 1) that ultimately brings in the leaf."""
        for n in self.nodes:
            if n.depth == 1:
                return n
        return None


@dataclass
class TreeAnalysis:
    paths: list[TreePath] = field(default_factory=list)

    def paths_for(self, ga: str) -> list[TreePath]:
        return [p for p in self.paths if p.leaf.ga == ga]

    def all_versions_of(self, ga: str) -> list[str]:
        return sorted({p.leaf.version for p in self.paths_for(ga)})

    def is_direct(self, ga: str) -> bool:
        for p in self.paths_for(ga):
            if p.leaf.depth == 1:
                return True
        return False


def _run_mvn(args: list[str], cwd: Path | str, timeout: int = MVN_TIMEOUT,
             check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["mvn", "-B", "-ntp", *args]
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise MavenError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc


# ------------------------------ dependency:tree ------------------------------

_TREE_LINE = re.compile(
    r"""^
        (?P<prefix>[\s|+\\\-]*?)             # ascii tree indent
        (?P<group>[\w.\-]+)
        :(?P<artifact>[\w.\-]+)
        :(?P<type>[\w.\-]+)
        :(?P<version>[\w.\-+]+)
        (?::(?P<scope>[\w\-]+))?
        (?:\s\(.*\))?                         # mediation/conflict marker
        \s*$
    """,
    re.VERBOSE,
)


def _strip_log_prefix(line: str) -> str:
    if line.startswith("[INFO] "):
        return line[len("[INFO] "):]
    return line


def _depth_from_prefix(prefix: str) -> int:
    """Maven dependency:tree uses 3 chars per level: '|  ' or '   ' then '+- '/'\\- '."""
    cleaned = prefix.rstrip()
    if not cleaned:
        return 0
    levels = 0
    i = 0
    while i < len(cleaned):
        chunk = cleaned[i:i + 3]
        if chunk in ("|  ", "   "):
            levels += 1
            i += 3
        elif chunk.startswith("+-") or chunk.startswith("\\-"):
            levels += 1
            i += 3
        else:
            i += 1
    return levels


def parse_dependency_tree(output: str) -> TreeAnalysis:
    """Parse `mvn dependency:tree` output into TreeAnalysis."""
    paths: list[TreePath] = []
    stack: list[TreeNode] = []
    for raw_line in output.splitlines():
        line = _strip_log_prefix(raw_line.rstrip())
        if not line.strip():
            continue
        m = _TREE_LINE.match(line)
        if not m:
            continue
        prefix = m.group("prefix") or ""
        depth = _depth_from_prefix(prefix)
        node = TreeNode(
            group_id=m.group("group"),
            artifact_id=m.group("artifact"),
            type=m.group("type"),
            version=m.group("version"),
            scope=m.group("scope") or "",
            depth=depth,
        )
        while stack and stack[-1].depth >= depth:
            stack.pop()
        stack.append(node)
        if depth > 0:
            paths.append(TreePath(nodes=tuple(stack)))
    return TreeAnalysis(paths=paths)


def dependency_tree(workdir: Path | str, ga: str | None = None) -> TreeAnalysis:
    args = ["dependency:tree", "-DoutputType=text"]
    if ga:
        args.append(f"-Dincludes={ga}")
    proc = _run_mvn(args, cwd=workdir)
    return parse_dependency_tree(proc.stdout)


# ------------------------------ effective pom -------------------------------

def effective_pom(workdir: Path | str) -> str:
    proc = _run_mvn(["help:effective-pom"], cwd=workdir)
    out = proc.stdout
    start = out.find("<?xml")
    if start == -1:
        start = out.find("<project")
    if start == -1:
        return ""
    end = out.rfind("</project>")
    if end == -1:
        return out[start:]
    return out[start:end + len("</project>")]


def effective_version(workdir: Path | str, ga: str) -> str | None:
    """Resolve current effective version of GA after all parent/BOM resolution."""
    tree = dependency_tree(workdir, ga=ga)
    versions = tree.all_versions_of(ga)
    if not versions:
        return None
    return versions[0]


# ------------------------------ available versions --------------------------

_VER_UPDATE_LINE = re.compile(
    r"^\[INFO\]\s+(?P<ga>[\w.\-]+:[\w.\-]+)\s+\.+\s+(?P<from>[\w.\-+]+)\s+->\s+(?P<to>[\w.\-+]+)\s*$"
)


def display_dependency_updates(workdir: Path | str, ga: str | None = None) -> dict[str, str]:
    """Returns {ga: latest_available_version}."""
    args = ["versions:display-dependency-updates"]
    if ga:
        args.append(f"-Dincludes={ga}")
    proc = _run_mvn(args, cwd=workdir, check=False)
    updates: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        m = _VER_UPDATE_LINE.match(line)
        if m:
            updates[m.group("ga")] = m.group("to")
    return updates


def probe_version_exists(workdir: Path | str, ga: str, version: str) -> bool:
    """Use dependency:get to check if a specific GAV resolves from configured repos."""
    artifact = f"{ga}:{version}"
    proc = _run_mvn(
        ["dependency:get", f"-Dartifact={artifact}", "-Dtransitive=false"],
        cwd=workdir,
        check=False,
    )
    return proc.returncode == 0


def list_available_versions(workdir: Path | str, ga: str) -> list[str]:
    """Returns versions newer than current effective, sorted newest first.

    Combines `versions:display-dependency-updates` (which only reports if dep is
    in the pom) with probe via `dependency:get`. For transitive deps where the
    plugin won't list anything, the caller may need to add a temporary entry
    first or supply candidate versions to probe.
    """
    updates = display_dependency_updates(workdir, ga=ga)
    if ga in updates:
        return [updates[ga]]
    return []


# ------------------------------ apply strategies ----------------------------

def bump_direct_version(workdir: Path | str, ga: str, version: str) -> None:
    _run_mvn(
        [
            "versions:use-dep-version",
            f"-Dincludes={ga}",
            f"-DdepVersion={version}",
            "-DforceVersion=true",
            "-DgenerateBackupPoms=false",
            "-DprocessDependencyManagement=false",
        ],
        cwd=workdir,
    )


def bump_managed_version(workdir: Path | str, ga: str, version: str) -> None:
    _run_mvn(
        [
            "versions:use-dep-version",
            f"-Dincludes={ga}",
            f"-DdepVersion={version}",
            "-DforceVersion=true",
            "-DgenerateBackupPoms=false",
            "-DprocessDependencyManagement=true",
            "-DprocessDependencies=false",
        ],
        cwd=workdir,
    )


def bump_parent_version(workdir: Path | str, ga: str, version: str) -> None:
    _run_mvn(
        [
            "versions:update-parent",
            f"-DparentVersion=[{version}]",
            "-DgenerateBackupPoms=false",
        ],
        cwd=workdir,
    )


# --- XML-level edits for cases Maven plugins don't cover ---

def add_dependency_management_override(pom_path: Path | str, ga: str, version: str) -> None:
    """Add or update a <dependencyManagement>/<dependencies>/<dependency> entry."""
    pom_path = Path(pom_path)
    tree = parse_pom(pom_path)
    root = tree.getroot()
    dm = root.find(_qname("dependencyManagement"))
    if dm is None:
        dm = etree.SubElement(root, _qname("dependencyManagement"))
    deps = dm.find(_qname("dependencies"))
    if deps is None:
        deps = etree.SubElement(dm, _qname("dependencies"))

    g, a = ga.split(":", 1)
    existing = None
    for dep in deps.findall(_qname("dependency")):
        eg = dep.find(_qname("groupId"))
        ea = dep.find(_qname("artifactId"))
        if eg is not None and ea is not None and (eg.text or "").strip() == g and (ea.text or "").strip() == a:
            existing = dep
            break

    if existing is not None:
        ver = existing.find(_qname("version"))
        if ver is None:
            ver = etree.SubElement(existing, _qname("version"))
        ver.text = version
    else:
        dep = etree.SubElement(deps, _qname("dependency"))
        etree.SubElement(dep, _qname("groupId")).text = g
        etree.SubElement(dep, _qname("artifactId")).text = a
        etree.SubElement(dep, _qname("version")).text = version

    _write_pom(tree, pom_path)


def bump_bom_import(pom_path: Path | str, ga: str, version: str) -> None:
    """Update version of an existing <scope>import</scope><type>pom</type> entry."""
    pom_path = Path(pom_path)
    tree = parse_pom(pom_path)
    root = tree.getroot()
    dm = root.find(_qname("dependencyManagement"))
    if dm is None:
        raise ValueError(f"No <dependencyManagement> in {pom_path}")
    deps = dm.find(_qname("dependencies"))
    if deps is None:
        raise ValueError(f"No <dependencyManagement>/<dependencies> in {pom_path}")
    g, a = ga.split(":", 1)
    for dep in deps.findall(_qname("dependency")):
        eg = (dep.findtext(_qname("groupId")) or "").strip()
        ea = (dep.findtext(_qname("artifactId")) or "").strip()
        scope = (dep.findtext(_qname("scope")) or "").strip()
        dtype = (dep.findtext(_qname("type")) or "").strip()
        if eg == g and ea == a and scope == "import" and dtype == "pom":
            ver = dep.find(_qname("version"))
            if ver is None:
                ver = etree.SubElement(dep, _qname("version"))
            ver.text = version
            _write_pom(tree, pom_path)
            return
    raise ValueError(f"BOM import {ga} not found in {pom_path}")


def add_exclusion_and_direct(
    pom_path: Path | str,
    parent_ga: str,
    vuln_ga: str,
    version: str,
) -> None:
    """In parent dep add <exclusion> for vuln_ga, then add vuln_ga as direct dep."""
    pom_path = Path(pom_path)
    tree = parse_pom(pom_path)
    root = tree.getroot()
    deps = root.find(_qname("dependencies"))
    if deps is None:
        raise ValueError(f"No top-level <dependencies> in {pom_path}")

    pg, pa = parent_ga.split(":", 1)
    parent_elem = None
    for dep in deps.findall(_qname("dependency")):
        if (
            (dep.findtext(_qname("groupId")) or "").strip() == pg
            and (dep.findtext(_qname("artifactId")) or "").strip() == pa
        ):
            parent_elem = dep
            break
    if parent_elem is None:
        raise ValueError(f"Parent dep {parent_ga} not found in {pom_path}")

    vg, va = vuln_ga.split(":", 1)
    exclusions = parent_elem.find(_qname("exclusions"))
    if exclusions is None:
        exclusions = etree.SubElement(parent_elem, _qname("exclusions"))
    already = False
    for exc in exclusions.findall(_qname("exclusion")):
        if (
            (exc.findtext(_qname("groupId")) or "").strip() == vg
            and (exc.findtext(_qname("artifactId")) or "").strip() == va
        ):
            already = True
            break
    if not already:
        exc = etree.SubElement(exclusions, _qname("exclusion"))
        etree.SubElement(exc, _qname("groupId")).text = vg
        etree.SubElement(exc, _qname("artifactId")).text = va

    # add direct dep with target version (or update if exists)
    existing_direct = None
    for dep in deps.findall(_qname("dependency")):
        if (
            (dep.findtext(_qname("groupId")) or "").strip() == vg
            and (dep.findtext(_qname("artifactId")) or "").strip() == va
        ):
            existing_direct = dep
            break
    if existing_direct is not None:
        ver = existing_direct.find(_qname("version"))
        if ver is None:
            ver = etree.SubElement(existing_direct, _qname("version"))
        ver.text = version
    else:
        new_dep = etree.SubElement(deps, _qname("dependency"))
        etree.SubElement(new_dep, _qname("groupId")).text = vg
        etree.SubElement(new_dep, _qname("artifactId")).text = va
        etree.SubElement(new_dep, _qname("version")).text = version

    _write_pom(tree, pom_path)


def _write_pom(tree: etree._ElementTree, path: Path) -> None:
    tree.write(
        str(path),
        xml_declaration=True,
        encoding="UTF-8",
        standalone=False,
    )


# ------------------------------ verification --------------------------------

def verify_vuln_resolved(workdir: Path | str, ga: str, vuln_version: str) -> dict:
    """Re-run dependency:tree; check that vuln_version no longer appears for ga."""
    tree = dependency_tree(workdir, ga=ga)
    versions = tree.all_versions_of(ga)
    if not versions:
        return {"resolved": True, "current_version": None,
                "note": "dep no longer in tree at all"}
    if vuln_version in versions:
        return {"resolved": False, "current_version": versions[0],
                "note": f"vulnerable {vuln_version} still in tree"}
    return {"resolved": True, "current_version": versions[0], "note": ""}
