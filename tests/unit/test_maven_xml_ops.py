from __future__ import annotations

from pathlib import Path

import pytest
from lxml import etree

from silent_updater.tools import maven_ops, pom_inspector


POM_NO_DM = """<?xml version='1.0' encoding='UTF-8'?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.10</version>
    </dependency>
  </dependencies>
</project>
"""


POM_WITH_DM = """<?xml version='1.0' encoding='UTF-8'?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.13.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""


POM_WITH_BOM = """<?xml version='1.0' encoding='UTF-8'?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>2.6.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""


POM_PARENT_DEP = """<?xml version='1.0' encoding='UTF-8'?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>2.6.0</version>
    </dependency>
  </dependencies>
</project>
"""


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "pom.xml"
    p.write_text(body, encoding="utf-8")
    return p


def test_add_dm_override_creates_section(tmp_path: Path) -> None:
    p = _write(tmp_path, POM_NO_DM)
    maven_ops.add_dependency_management_override(p, "com.foo:bar", "1.2.3")
    managed = pom_inspector.list_managed_dependencies(p)
    assert any(d.ga == "com.foo:bar" and d.version == "1.2.3" for d in managed)


def test_add_dm_override_updates_existing(tmp_path: Path) -> None:
    p = _write(tmp_path, POM_WITH_DM)
    maven_ops.add_dependency_management_override(
        p, "com.fasterxml.jackson.core:jackson-databind", "2.17.1"
    )
    managed = pom_inspector.list_managed_dependencies(p)
    versions = {d.ga: d.version for d in managed}
    assert versions["com.fasterxml.jackson.core:jackson-databind"] == "2.17.1"


def test_bump_bom_import_updates_version(tmp_path: Path) -> None:
    p = _write(tmp_path, POM_WITH_BOM)
    maven_ops.bump_bom_import(
        p, "org.springframework.boot:spring-boot-dependencies", "2.7.18"
    )
    boms = pom_inspector.list_bom_imports(p)
    assert boms[0].version == "2.7.18"


def test_bump_bom_import_raises_if_not_found(tmp_path: Path) -> None:
    p = _write(tmp_path, POM_NO_DM)
    with pytest.raises(ValueError):
        maven_ops.bump_bom_import(p, "com.foo:bom", "1.0.0")


def test_add_exclusion_and_direct(tmp_path: Path) -> None:
    p = _write(tmp_path, POM_PARENT_DEP)
    maven_ops.add_exclusion_and_direct(
        p,
        parent_ga="org.springframework.boot:spring-boot-starter-web",
        vuln_ga="org.foo:vulnerable",
        version="2.0.0",
    )
    # parse and check structure
    tree = pom_inspector.parse_pom(p)
    root = tree.getroot()
    deps = root.find(f"{{{pom_inspector.MAVEN_NS}}}dependencies")
    assert deps is not None
    parent_dep = None
    direct = None
    for d in deps.findall(f"{{{pom_inspector.MAVEN_NS}}}dependency"):
        a = d.findtext(f"{{{pom_inspector.MAVEN_NS}}}artifactId")
        if a == "spring-boot-starter-web":
            parent_dep = d
        if a == "vulnerable":
            direct = d
    assert parent_dep is not None
    exclusions = parent_dep.find(f"{{{pom_inspector.MAVEN_NS}}}exclusions")
    assert exclusions is not None
    exc = exclusions.find(f"{{{pom_inspector.MAVEN_NS}}}exclusion")
    assert exc is not None
    assert exc.findtext(f"{{{pom_inspector.MAVEN_NS}}}artifactId") == "vulnerable"
    assert direct is not None
    assert direct.findtext(f"{{{pom_inspector.MAVEN_NS}}}version") == "2.0.0"
