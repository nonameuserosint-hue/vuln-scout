from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "artifacts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


artifact_utils = load_module("artifact_utils", SCRIPTS_DIR / "artifact_utils.py")


class ArtifactTests(unittest.TestCase):
    def test_sample_artifact_matches_schema_contract(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        errors = artifact_utils.validate_findings_artifact(artifact)
        self.assertEqual(errors, [])

    def test_suppressions_recompute_summary(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        suppressions = artifact_utils.parse_suppressions(FIXTURES_DIR / "sample.vuln-scout-ignore")
        updated = artifact_utils.apply_suppressions(artifact, suppressions)

        self.assertTrue(updated["findings"][2]["suppressed"])
        self.assertEqual(updated["summary"]["total_findings"], 1)
        self.assertEqual(updated["summary"]["high"], 0)
        self.assertEqual(updated["summary"]["total_hotspots"], 1)

    def test_sarif_conversion_emits_only_reportable_findings(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        sarif = artifact_utils.to_sarif(artifact)
        self.assertEqual(sarif["version"], "2.1.0")

        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        uris = [result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"]]
        self.assertNotIn("tests/fixtures/code/js/nextjs-redirect/app/actions.ts", uris)

    def test_cli_writes_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "findings.sarif.json"
            artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
            sarif = artifact_utils.to_sarif(artifact)
            artifact_utils.dump_json(sarif, output_path)
            written = json.loads(output_path.read_text())
            self.assertEqual(written["runs"][0]["tool"]["driver"]["name"], "VulnScout")


if __name__ == "__main__":
    unittest.main()
