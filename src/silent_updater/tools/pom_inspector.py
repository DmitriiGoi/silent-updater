from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lxml import etree

MAVEN_NS = "http://maven.apache.org/POM/4.0.0"
NSMAP = {"m": MAVEN_NS}


@dataclass(frozen=True)
class Dependency:
    group_id: str
    artifact_id: str
    version: str | None
    scope: str | None
    type: str | None
    in_management: bool

    @property
    def ga(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


@dataclass(frozen=True)
class ParentRef:
    group_id: str
    artifact_id: str
    version: str

    @property
    def ga(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


def parse_pom(pom_path: Path | str) -> etree._ElementTree:
    parser = etree.XMLParser(remove_blank_text=False, strip_cdata=False)
    return etree.parse(str(pom_path), parser=parser)


def _qname(tag: str) -> str:
    return f"{{{MAVEN_NS}}}{tag}"


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _text(elem: etree._Element | None, child: str) -> str | None:
    if elem is None:
        return None
    found = elem.find(_qname(child))
    if found is None:
        return None
    if found.text is None:
        return None
    return found.text.strip() or None


def get_parent(tree: etree._ElementTree) -> ParentRef | None:
    root = tree.getroot()
    parent = root.find(_qname("parent"))
    if parent is None:
        return None
    g = _text(parent, "groupId")
    a = _text(parent, "artifactId")
    v = _text(parent, "version")
    if not (g and a and v):
        return None
    return ParentRef(group_id=g, artifact_id=a, version=v)


def _iter_dependencies(container: etree._Element | None,
                      in_management: bool) -> list[Dependency]:
    if container is None:
        return []
    deps: list[Dependency] = []
    for dep_elem in container.findall(_qname("dependency")):
        g = _text(dep_elem, "groupId")
        a = _text(dep_elem, "artifactId")
        if not (g and a):
            continue
        deps.append(
            Dependency(
                group_id=g,
                artifact_id=a,
                version=_text(dep_elem, "version"),
                scope=_text(dep_elem, "scope"),
                type=_text(dep_elem, "type"),
                in_management=in_management,
            )
        )
    return deps


def list_direct_dependencies(pom_path: Path | str) -> list[Dependency]:
    tree = parse_pom(pom_path)
    root = tree.getroot()
    container = root.find(_qname("dependencies"))
    return _iter_dependencies(container, in_management=False)


def list_managed_dependencies(pom_path: Path | str) -> list[Dependency]:
    tree = parse_pom(pom_path)
    root = tree.getroot()
    dm = root.find(_qname("dependencyManagement"))
    if dm is None:
        return []
    container = dm.find(_qname("dependencies"))
    return _iter_dependencies(container, in_management=True)


def list_bom_imports(pom_path: Path | str) -> list[Dependency]:
    """Returns dependencies in <dependencyManagement> with scope=import + type=pom."""
    return [
        d for d in list_managed_dependencies(pom_path)
        if d.scope == "import" and d.type == "pom"
    ]


def find_dependency(pom_path: Path | str, ga: str) -> Dependency | None:
    for d in list_direct_dependencies(pom_path):
        if d.ga == ga:
            return d
    for d in list_managed_dependencies(pom_path):
        if d.ga == ga:
            return d
    return None


def discover_pom_files(root_dir: Path | str) -> list[Path]:
    root = Path(root_dir)
    return sorted(root.rglob("pom.xml"))


def find_root_pom(workdir: Path | str) -> Path:
    workdir = Path(workdir)
    candidate = workdir / "pom.xml"
    if candidate.exists():
        return candidate
    poms = discover_pom_files(workdir)
    if not poms:
        raise FileNotFoundError(f"No pom.xml found under {workdir}")
    return poms[0]
