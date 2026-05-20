from __future__ import annotations

from silent_updater.tools.maven_ops import parse_dependency_tree


TREE_SIMPLE = """\
[INFO] --- maven-dependency-plugin:3.6.1:tree (default-cli) @ app ---
[INFO] com.example:app:jar:1.0.0
[INFO] +- org.apache.commons:commons-lang3:jar:3.10:compile
[INFO] +- com.fasterxml.jackson.core:jackson-databind:jar:2.13.0:compile
[INFO] |  +- com.fasterxml.jackson.core:jackson-annotations:jar:2.13.0:compile
[INFO] |  \\- com.fasterxml.jackson.core:jackson-core:jar:2.13.0:compile
[INFO] \\- org.springframework:spring-core:jar:5.3.0:compile
[INFO]    \\- org.springframework:spring-jcl:jar:5.3.0:compile
[INFO] ------------------------------------------------------------------------
"""


def test_parses_root_and_direct() -> None:
    analysis = parse_dependency_tree(TREE_SIMPLE)
    assert analysis.is_direct("org.apache.commons:commons-lang3")
    assert analysis.is_direct("com.fasterxml.jackson.core:jackson-databind")
    assert analysis.is_direct("org.springframework:spring-core")


def test_parses_transitive() -> None:
    analysis = parse_dependency_tree(TREE_SIMPLE)
    paths = analysis.paths_for("com.fasterxml.jackson.core:jackson-annotations")
    assert len(paths) == 1
    leaf = paths[0].leaf
    assert leaf.ga == "com.fasterxml.jackson.core:jackson-annotations"
    assert leaf.version == "2.13.0"
    assert leaf.depth == 2
    assert paths[0].root_dep is not None
    assert paths[0].root_dep.ga == "com.fasterxml.jackson.core:jackson-databind"


def test_parses_deeper_transitive() -> None:
    analysis = parse_dependency_tree(TREE_SIMPLE)
    paths = analysis.paths_for("org.springframework:spring-jcl")
    assert len(paths) == 1
    assert paths[0].leaf.depth == 2
    assert paths[0].root_dep is not None
    assert paths[0].root_dep.ga == "org.springframework:spring-core"


def test_all_versions_unique() -> None:
    analysis = parse_dependency_tree(TREE_SIMPLE)
    versions = analysis.all_versions_of("com.fasterxml.jackson.core:jackson-databind")
    assert versions == ["2.13.0"]
