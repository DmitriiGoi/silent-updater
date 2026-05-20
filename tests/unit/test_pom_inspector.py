from __future__ import annotations

from pathlib import Path

from silent_updater.tools import pom_inspector


POM_SIMPLE = """<?xml version="1.0" encoding="UTF-8"?>
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
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
"""


POM_BOM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.6.0</version>
  </parent>
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


def test_list_direct(tmp_path: Path) -> None:
    p = tmp_path / "pom.xml"
    p.write_text(POM_SIMPLE, encoding="utf-8")
    deps = pom_inspector.list_direct_dependencies(p)
    gas = {d.ga: d.version for d in deps}
    assert gas == {
        "org.apache.commons:commons-lang3": "3.10",
        "com.fasterxml.jackson.core:jackson-databind": "2.13.0",
    }


def test_parent_and_bom(tmp_path: Path) -> None:
    p = tmp_path / "pom.xml"
    p.write_text(POM_BOM, encoding="utf-8")
    parent = pom_inspector.get_parent(pom_inspector.parse_pom(p))
    assert parent is not None
    assert parent.ga == "org.springframework.boot:spring-boot-starter-parent"
    assert parent.version == "2.6.0"

    boms = pom_inspector.list_bom_imports(p)
    assert len(boms) == 1
    assert boms[0].ga == "org.springframework.boot:spring-boot-dependencies"


def test_find_dependency(tmp_path: Path) -> None:
    p = tmp_path / "pom.xml"
    p.write_text(POM_SIMPLE, encoding="utf-8")
    found = pom_inspector.find_dependency(p, "org.apache.commons:commons-lang3")
    assert found is not None
    assert found.version == "3.10"

    missing = pom_inspector.find_dependency(p, "no:such")
    assert missing is None


def test_discover_pom_files(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(POM_SIMPLE, encoding="utf-8")
    sub = tmp_path / "mod"
    sub.mkdir()
    (sub / "pom.xml").write_text(POM_SIMPLE, encoding="utf-8")
    found = pom_inspector.discover_pom_files(tmp_path)
    assert len(found) == 2
    root = pom_inspector.find_root_pom(tmp_path)
    assert root == tmp_path / "pom.xml"
