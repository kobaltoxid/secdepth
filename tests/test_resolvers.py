import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "secdepth" / "scripts"))

import inventory  # noqa: E402
import resolve  # noqa: E402

CARGO_LOCK = """
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "tempfile"]

[[package]]
name = "serde"
version = "1.0.150"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde_derive 1.0.150"]

[[package]]
name = "serde_derive"
version = "1.0.150"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tempfile"
version = "3.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://example.test/forked#abc"
"""
CARGO_TOML = '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n[dev-dependencies]\ntempfile = "3"\n'

POETRY_LOCK = """
[[package]]
name = "Jinja2"
version = "2.10"
[package.dependencies]
MarkupSafe = ">=0.23"

[[package]]
name = "markupsafe"
version = "1.1.1"

[[package]]
name = "pytest"
version = "7.0.0"
"""
PYPROJECT = """
[tool.poetry]
name = "svc"
version = "1.2.0"
[tool.poetry.dependencies]
python = "^3.11"
jinja2 = "2.10"
[tool.poetry.group.dev.dependencies]
pytest = "7.0.0"
"""
UV_LOCK = """
version = 1

[[package]]
name = "svc"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "requests"
version = "2.25.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
"""
GO_MOD = """module example.com/svc

go 1.21

toolchain go1.21.3

require (
\tgolang.org/x/net v0.17.0
\tgolang.org/x/text v0.13.0 // indirect
)

require github.com/google/uuid v1.3.0
"""
NUGET_LOCK = {"version": 1, "dependencies": {"net8.0": {
    "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1", "dependencies": {}},
    "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},
    "Lib": {"type": "Project"}}}}
GRADLE_LOCK = """# This is a Gradle generated file
org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
junit:junit:4.12=testCompileClasspath,testRuntimeClasspath
empty=
"""
POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId><artifactId>svc</artifactId><version>1.0.0</version>
  <properties><jackson.version>2.9.8</jackson.version></properties>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
  </dependencies>
</project>
"""


class ResolverTests(unittest.TestCase):
    def project(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content if isinstance(content, str) else json.dumps(content))
        data = resolve.resolve_project(root, generate=False)
        self.assertEqual(inventory.validate(data), [])
        return data, {c["id"]: c for c in data["components"]}

    def test_cargo(self):
        data, c = self.project({"Cargo.lock": CARGO_LOCK, "Cargo.toml": CARGO_TOML})
        self.assertEqual(data["root_component_id"], "crates.io:app@0.1.0")
        self.assertEqual(c["crates.io:serde@1.0.150"]["scope"], "runtime")
        self.assertEqual(c["crates.io:serde_derive@1.0.150"]["scope"], "runtime")
        self.assertEqual(c["crates.io:tempfile@3.3.0"]["scope"], "dev")
        self.assertEqual(c["crates.io:serde@1.0.150"]["depends_on"], ["crates.io:serde_derive@1.0.150"])
        self.assertIn("Cargo.lock#forked", [e["path"] for e in data["coverage"]["entries"]])

    def test_poetry(self):
        data, c = self.project({"poetry.lock": POETRY_LOCK, "pyproject.toml": PYPROJECT, "requirements.txt": "flask\n"})
        self.assertEqual(data["root_component_id"], "PyPI:svc@1.2.0")
        self.assertEqual((c["PyPI:jinja2@2.10"]["scope"], c["PyPI:jinja2@2.10"]["direct"]), ("runtime", True))
        self.assertEqual(c["PyPI:markupsafe@1.1.1"]["scope"], "runtime")
        self.assertEqual(c["PyPI:pytest@7.0.0"]["scope"], "dev")
        reasons = {e["path"]: e["reason"] for e in data["coverage"]["entries"]}
        self.assertEqual(reasons["requirements.txt"], "covered by poetry.lock")

    def test_uv(self):
        _, c = self.project({"uv.lock": UV_LOCK})
        self.assertEqual(c["PyPI:urllib3@1.26.4"]["scope"], "runtime")
        self.assertEqual(c["PyPI:pytest@8.0.0"]["scope"], "dev")
        self.assertNotIn("PyPI:svc@0.1.0", [k for k, v in c.items() if not v.get("root")])

    def test_requirements_pins_and_gaps(self):
        data, c = self.project({"requirements.txt": "Django==3.2.0\nrequests>=2\n-r other.txt\n"})
        self.assertIn("PyPI:django@3.2.0", c)
        reasons = " ".join(e["reason"] or "" for e in data["coverage"]["entries"])
        self.assertIn("not pinned", reasons)
        self.assertIn("not followed", reasons)
        self.assertFalse(data["coverage"]["complete"])

    def test_go_mod(self):
        data, c = self.project({"go.mod": GO_MOD})
        self.assertEqual(data["root_component_id"], "Go:example.com/svc@unknown")
        self.assertTrue(c["Go:golang.org/x/net@0.17.0"]["direct"])
        self.assertFalse(c["Go:golang.org/x/text@0.13.0"]["direct"])
        self.assertIn("Go:github.com/google/uuid@1.3.0", c)
        self.assertIn("Go:stdlib@1.21.3", c)

    def test_nuget(self):
        _, c = self.project({"packages.lock.json": NUGET_LOCK})
        self.assertTrue(c["NuGet:Newtonsoft.Json@12.0.1"]["direct"])
        self.assertFalse(c["NuGet:System.Text.Json@8.0.0"]["direct"])
        self.assertFalse(any(k.startswith("NuGet:Lib") for k in c))

    def test_gradle_lockfile(self):
        _, c = self.project({"gradle.lockfile": GRADLE_LOCK, "build.gradle": "plugins {}\n"})
        self.assertEqual(c["Maven:org.apache.logging.log4j:log4j-core@2.14.1"]["scope"], "runtime")
        self.assertEqual(c["Maven:junit:junit@4.12"]["scope"], "dev")

    def test_pom_direct_only(self):
        data, c = self.project({"pom.xml": POM})
        self.assertEqual(data["root_component_id"], "Maven:com.acme:svc@1.0.0")
        self.assertIn("Maven:com.fasterxml.jackson.core:jackson-databind@2.9.8", c)
        self.assertEqual(c["Maven:junit:junit@4.12"]["scope"], "dev")
        reasons = {e["path"]: e["reason"] for e in data["coverage"]["entries"]}
        self.assertIn("managed elsewhere", reasons["pom.xml#org.slf4j:slf4j-api"])
        self.assertIn("transitive", reasons["pom.xml#transitive"])
        self.assertFalse(data["coverage"]["complete"])

    def test_broken_manifest_is_a_gap(self):
        data, _ = self.project({"Cargo.lock": "not = [valid", "Cargo.toml": CARGO_TOML})
        entry = next(e for e in data["coverage"]["entries"] if e["path"] == "Cargo.lock")
        self.assertEqual(entry["status"], "unidentified")
        self.assertIn("could not parse", entry["reason"])


if __name__ == "__main__":
    unittest.main()
