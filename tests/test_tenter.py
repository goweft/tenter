#!/usr/bin/env python3
"""Tests for weft-publish-guard."""

import json
import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tenter.core import (
    PublishGuard,
    ScanResult,
    Severity,
    format_human,
    format_json,
    format_sarif,
    detect_package_type,
    main,
)


def make_temp_dir_with_files(files: dict) -> str:
    """Create a temp dir with the given files. Keys are relative paths, values are content (str or bytes)."""
    tmpdir = tempfile.mkdtemp()
    for rel_path, content in files.items():
        full = Path(tmpdir) / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            full.write_bytes(content)
        else:
            full.write_text(content)
    return tmpdir


def make_tarball(files: dict) -> str:
    """Create a .tgz tarball with the given files."""
    tmpdir = tempfile.mkdtemp()
    tarball_path = os.path.join(tmpdir, "test-package.tgz")

    with tarfile.open(tarball_path, "w:gz") as tar:
        for rel_path, content in files.items():
            content_bytes = content.encode() if isinstance(content, str) else content
            import io
            info = tarfile.TarInfo(name=f"package/{rel_path}")
            info.size = len(content_bytes)
            tar.addfile(info, io.BytesIO(content_bytes))

    return tarball_path


def make_wheel(files: dict) -> str:
    """Create a .whl file with the given files."""
    tmpdir = tempfile.mkdtemp()
    wheel_path = os.path.join(tmpdir, "test_package-0.1.0-py3-none-any.whl")

    with zipfile.ZipFile(wheel_path, "w") as zf:
        for rel_path, content in files.items():
            content_bytes = content.encode() if isinstance(content, str) else content
            zf.writestr(rel_path, content_bytes)

    return wheel_path


# ─── Test Cases ──────────────────────────────────────────────────────────────

class TestSourceMapDetection:
    """Tests for MAP-001 and MAP-002 rules."""

    def test_detects_map_file(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js": "console.log('hello');",
            "dist/index.js.map": '{"version":3,"sources":["../src/index.ts"]}',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        map_findings = [f for f in result.findings if f.rule_id == "MAP-001"]
        assert len(map_findings) == 1, f"Expected 1 MAP-001, got {len(map_findings)}"
        assert map_findings[0].severity == Severity.CRITICAL

    def test_detects_sourcemapping_url_external(self):
        js_content = b"console.log('hello');\n//# sourceMappingURL=https://r2.example.com/src.zip"
        tmpdir = make_temp_dir_with_files({
            "dist/bundle.js": js_content,
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        url_findings = [f for f in result.findings if f.rule_id == "MAP-002"]
        assert len(url_findings) == 1
        assert url_findings[0].severity == Severity.CRITICAL

    def test_detects_sourcemapping_url_local(self):
        js_content = b"console.log('hello');\n//# sourceMappingURL=index.js.map"
        tmpdir = make_temp_dir_with_files({
            "dist/bundle.js": js_content,
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        url_findings = [f for f in result.findings if f.rule_id == "MAP-002"]
        assert len(url_findings) == 1
        assert url_findings[0].severity == Severity.HIGH

    def test_clean_js_no_findings(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js": "console.log('hello');",
            "package.json": '{"name":"test","version":"1.0.0"}',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        assert len(result.findings) == 0


class TestSecretDetection:
    """Tests for SEC-001 and SEC-002 rules."""

    def test_detects_env_file(self):
        tmpdir = make_temp_dir_with_files({
            ".env": "DATABASE_URL=postgres://user:pass@localhost/db",
            "index.js": "require('dotenv');",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        sec_findings = [f for f in result.findings if f.rule_id == "SEC-001"]
        assert len(sec_findings) >= 1

    def test_detects_private_key(self):
        key_content = b"-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----"
        tmpdir = make_temp_dir_with_files({
            "certs/server.key": key_content,
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        # Should trigger both SEC-001 (*.key pattern) and SEC-002 (private key regex)
        assert any(f.rule_id == "SEC-002" for f in result.findings)

    def test_detects_aws_key(self):
        tmpdir = make_temp_dir_with_files({
            "config.js": b'const key = "AKIAIOSFODNN7EXAMPLE";',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        aws_findings = [f for f in result.findings
                        if f.rule_id == "SEC-002" and "AWS" in f.message]
        assert len(aws_findings) >= 1

    def test_detects_github_token(self):
        tmpdir = make_temp_dir_with_files({
            "deploy.sh": b'export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        gh_findings = [f for f in result.findings
                       if f.rule_id == "SEC-002" and "GitHub" in f.message]
        assert len(gh_findings) >= 1

    def test_detects_npmrc(self):
        tmpdir = make_temp_dir_with_files({
            ".npmrc": "//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        # Both SEC-001 (.npmrc file) and SEC-002 (npm token pattern)
        assert any(f.rule_id == "SEC-001" for f in result.findings)


class TestDebugArtifacts:
    """Tests for DBG-001 rule."""

    def test_detects_pdb_file(self):
        tmpdir = make_temp_dir_with_files({
            "bin/app.pdb": b"\x00" * 100,
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        dbg = [f for f in result.findings if f.rule_id == "DBG-001"]
        assert len(dbg) >= 1

    def test_detects_src_zip(self):
        tmpdir = make_temp_dir_with_files({
            "dist/src.zip": b"PK\x03\x04fake",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        dbg = [f for f in result.findings if f.rule_id == "DBG-001"]
        assert len(dbg) >= 1


class TestInternalArtifacts:
    """Tests for INT-001 rule."""

    def test_detects_claude_config(self):
        tmpdir = make_temp_dir_with_files({
            ".claude/config.json": '{"model":"opus"}',
            "index.js": "console.log('hello');",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        int_findings = [f for f in result.findings if f.rule_id == "INT-001"]
        assert len(int_findings) >= 1

    def test_detects_claude_md(self):
        tmpdir = make_temp_dir_with_files({
            "CLAUDE.md": "# Internal instructions for Claude Code",
            "index.js": "console.log('hello');",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        int_findings = [f for f in result.findings if f.rule_id == "INT-001"]
        assert len(int_findings) >= 1

    def test_detects_coverage_dir(self):
        tmpdir = make_temp_dir_with_files({
            "coverage/lcov.info": "TN:\nSF:src/index.ts",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        int_findings = [f for f in result.findings if f.rule_id == "INT-001"]
        assert len(int_findings) >= 1


class TestSizeChecks:
    """Tests for SIZE rules."""

    def test_detects_large_file(self):
        tmpdir = make_temp_dir_with_files({
            "dist/huge.js.map": b"x" * (51 * 1024 * 1024),  # 51 MB
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        size_findings = [f for f in result.findings if f.rule_id == "SIZE-001"]
        assert len(size_findings) >= 1
        assert size_findings[0].severity == Severity.CRITICAL


class TestTarballScanning:
    """Tests for tarball-based scanning."""

    def test_scan_tarball_with_map(self):
        tarball = make_tarball({
            "dist/index.js": "console.log('ok');",
            "dist/index.js.map": '{"version":3}',
        })
        guard = PublishGuard()
        result = guard.scan_npm_tarball(tarball)
        assert result.package_type == "npm"
        assert any(f.rule_id == "MAP-001" for f in result.findings)

    def test_clean_tarball(self):
        tarball = make_tarball({
            "dist/index.js": "console.log('ok');",
            "package.json": '{"name":"clean","version":"1.0.0"}',
        })
        guard = PublishGuard()
        result = guard.scan_npm_tarball(tarball)
        assert len(result.findings) == 0


class TestWheelScanning:
    """Tests for .whl scanning."""

    def test_scan_wheel_with_env(self):
        wheel = make_wheel({
            "my_package/__init__.py": "pass",
            ".env": "SECRET=hunter2",
        })
        guard = PublishGuard()
        result = guard.scan_pip_sdist(wheel)
        assert result.package_type == "pip"
        assert any(f.rule_id == "SEC-001" for f in result.findings)


class TestAllowlist:
    """Tests for allowlist functionality."""

    def test_allowlist_skips_file(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js.map": '{"version":3}',
        })
        guard = PublishGuard(config={"allowlist": ["*.map"]})
        result = guard.scan_directory(tmpdir)
        assert len(result.findings) == 0

    def test_allowlist_partial(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js.map": '{"version":3}',
            ".env": "SECRET=x",
        })
        guard = PublishGuard(config={"allowlist": ["*.map"]})
        result = guard.scan_directory(tmpdir)
        # .map should be skipped but .env should still be caught
        assert not any(f.rule_id == "MAP-001" for f in result.findings)
        assert any(f.rule_id == "SEC-001" for f in result.findings)


class TestOutputFormatters:
    """Tests for output formatting."""

    def test_json_output(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js.map": '{"version":3}',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        output = format_json(result)
        parsed = json.loads(output)
        assert "findings" in parsed
        assert parsed["findings_count"] >= 1

    def test_sarif_output(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js.map": '{"version":3}',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        output = format_sarif(result)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1
        assert len(parsed["runs"][0]["results"]) >= 1

    def test_human_output_clean(self):
        tmpdir = make_temp_dir_with_files({
            "index.js": "console.log('clean');",
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        output = format_human(result, use_color=False)
        assert "No issues found" in output

    def test_human_output_findings(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js.map": '{"version":3}',
        })
        guard = PublishGuard()
        result = guard.scan_directory(tmpdir)
        output = format_human(result, use_color=False)
        assert "CRITICAL" in output
        assert "MAP-001" in output


class TestAutoDetection:
    """Tests for package type auto-detection."""

    def test_detect_npm(self):
        tmpdir = make_temp_dir_with_files({"package.json": "{}"})
        assert detect_package_type(tmpdir) == "npm"

    def test_detect_pip(self):
        tmpdir = make_temp_dir_with_files({"pyproject.toml": "[build-system]"})
        assert detect_package_type(tmpdir) == "pip"

    def test_detect_cargo(self):
        tmpdir = make_temp_dir_with_files({"Cargo.toml": "[package]"})
        assert detect_package_type(tmpdir) == "cargo"


class TestCLI:
    """Tests for CLI entry point."""

    def test_scan_command(self):
        tmpdir = make_temp_dir_with_files({
            "index.js": "console.log('clean');",
        })
        code = main(["scan", tmpdir, "--format", "json", "--no-color"])
        assert code == 0

    def test_scan_with_findings(self):
        tmpdir = make_temp_dir_with_files({
            "dist/index.js.map": '{"version":3}',
        })
        code = main(["scan", tmpdir, "--format", "json", "--no-color"])
        assert code == 2  # CRITICAL finding

    def test_fail_on_threshold(self):
        tmpdir = make_temp_dir_with_files({
            "coverage/lcov.info": "TN:",  # INT-001 = MEDIUM
        })
        # Default --fail-on=high, MEDIUM shouldn't fail
        code = main(["scan", tmpdir, "--format", "json", "--no-color"])
        assert code == 0

        # --fail-on=medium should fail
        code = main(["scan", tmpdir, "--format", "json", "--no-color", "--fail-on", "medium"])
        assert code == 2

    def test_no_args_prints_help(self):
        code = main([])
        assert code == 0


# ─── Runner ──────────────────────────────────────────────────────────────────

def run_tests():
    """Simple test runner. No dependencies required."""
    test_classes = [
        TestSourceMapDetection,
        TestSecretDetection,
        TestDebugArtifacts,
        TestInternalArtifacts,
        TestSizeChecks,
        TestTarballScanning,
        TestWheelScanning,
        TestAllowlist,
        TestOutputFormatters,
        TestAutoDetection,
        TestCLI,
    ]

    total = 0
    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        for method_name in methods:
            total += 1
            method = getattr(instance, method_name)
            test_label = f"{cls.__name__}.{method_name}"
            try:
                method()
                passed += 1
                print(f"  \033[92m✓\033[0m {test_label}")
            except Exception as e:
                failed += 1
                errors.append((test_label, e))
                print(f"  \033[91m✖\033[0m {test_label}: {e}")

    print(f"\n{'═' * 60}")
    print(f"  Total: {total}  Passed: {passed}  Failed: {failed}")
    if errors:
        print(f"\n  Failures:")
        for label, err in errors:
            print(f"    {label}: {err}")
    print(f"{'═' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
