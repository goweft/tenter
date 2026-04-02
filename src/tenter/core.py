#!/usr/bin/env python3
"""
tenter — Pre-publish artifact integrity scanner.

Inspects package artifacts (npm, pip, cargo) before publish to detect
accidental inclusion of debug artifacts, source maps, secrets, internal
documentation, and other sensitive files that should never ship.

Born from the Claude Code npm source map leak (March 31, 2026).

Zero external dependencies. Uses only Python stdlib.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"

# ─── Severity ────────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def exit_code(self) -> int:
        return {
            Severity.CRITICAL: 2,
            Severity.HIGH: 2,
            Severity.MEDIUM: 1,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "\033[91m",  # Red
            Severity.HIGH: "\033[91m",      # Red
            Severity.MEDIUM: "\033[93m",    # Yellow
            Severity.LOW: "\033[96m",       # Cyan
            Severity.INFO: "\033[90m",      # Gray
        }[self]


# ─── Findings ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file_path: str
    message: str
    detail: str = ""

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "message": self.message,
        }
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class ScanResult:
    package_type: str
    package_path: str
    total_files: int
    total_size_bytes: int
    findings: list = field(default_factory=list)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    @property
    def exit_code(self) -> int:
        ms = self.max_severity
        return ms.exit_code if ms else 0

    def to_dict(self) -> dict:
        return {
            "version": __version__,
            "package_type": self.package_type,
            "package_path": self.package_path,
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "findings_count": len(self.findings),
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.findings],
        }


# ─── Rule Definitions ────────────────────────────────────────────────────────

# Source map patterns
SOURCE_MAP_EXTENSIONS = {
    ".map", ".js.map", ".css.map", ".ts.map", ".mjs.map", ".cjs.map",
}

SOURCE_MAP_URL_PATTERN = re.compile(
    rb"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.IGNORECASE
)

# Debug artifact patterns
DEBUG_ARTIFACT_PATTERNS = [
    "*.map",
    "*.pdb",           # Windows debug symbols
    "*.dSYM",          # macOS debug symbols
    "*.dwarf",
    "*.debug",
    "*.dbg",
    "*.sym",
    "*.sourcemap",
    "**/src.zip",       # Exactly what Claude Code leaked
    "**/.debug/",
]

# Sensitive file patterns
SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".env.*",
    "*.env",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    "**/.git-credentials",
    "**/id_rsa",
    "**/id_ed25519",
    "**/id_ecdsa",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/credentials.json",
    "**/service-account*.json",
    "**/.htpasswd",
    "**/.netrc",
    "**/token.json",
    "**/secrets.yaml",
    "**/secrets.yml",
    "**/secrets.json",
    "**/.docker/config.json",
    "**/kubeconfig",
]

# Internal / development artifact patterns
INTERNAL_ARTIFACT_PATTERNS = [
    "**/.claude/**",
    "**/CLAUDE.md",
    "**/.cursor/**",
    "**/.vscode/settings.json",
    "**/.idea/**",
    "**/tsconfig.tsbuildinfo",
    "**/.eslintcache",
    "**/coverage/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/node_modules/**",
    "**/.git/**",
    "**/Thumbs.db",
    "**/.DS_Store",
    "**/.internal/**",
    "**/.internal.*",
    "**/TODO.internal*",
    "**/NOTES.internal*",
]

# Secret patterns (regex) — checked against file contents.
#
# Design constraints for ReDoS safety:
#   - Prefer anchored or fixed-length quantifiers where the token format allows it.
#   - Use specific character classes ([A-Za-z0-9/+=]) instead of broad ones (\S)
#     to minimise backtracking surface on dense minified content.
#   - The scanning loop uses search() (short-circuit) not findall(), and enforces
#     a per-file time budget (CONTENT_SCAN_TIMEOUT_SECS). Any new pattern added
#     here must not rely on the loop running to exhaustion.
SECRET_PATTERNS = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    # \S{20,} replaced with [A-Za-z0-9/+=]{20,} — tighter class, same real-world
    # coverage, eliminates backtracking on non-whitespace-dense minified JS.
    (re.compile(rb"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{20,}"), "AWS Secret Key"),
    (re.compile(rb"ghp_[a-zA-Z0-9]{36,}"), "GitHub Personal Access Token"),
    (re.compile(rb"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth Token"),
    (re.compile(rb"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"), "GitHub Fine-Grained PAT"),
    (re.compile(rb"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"), "OpenAI API Key"),
    (re.compile(rb"sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}"), "Anthropic API Key"),
    (re.compile(rb"xox[boaprs]-[0-9]{10,}-[a-zA-Z0-9\-]+"), "Slack Token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(rb"(?:npm_)[a-zA-Z0-9]{36}"), "npm Access Token"),
    (re.compile(rb"pypi-[a-zA-Z0-9\-_]{100,}"), "PyPI API Token"),
    (re.compile(rb"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), "Hardcoded Password"),
    (re.compile(rb"(?:api_key|apikey|api-key)\s*[=:]\s*['\"][^'\"]{16,}['\"]", re.IGNORECASE), "Hardcoded API Key"),
    (re.compile(rb"Bearer\s+[a-zA-Z0-9\-_.~+/]{20,}"), "Bearer Token"),
]

# Anomalous size thresholds (bytes)
SINGLE_FILE_SIZE_WARN = 10 * 1024 * 1024     # 10 MB
SINGLE_FILE_SIZE_CRIT = 50 * 1024 * 1024     # 50 MB (Claude Code's map was 59.8 MB)
TOTAL_PACKAGE_SIZE_WARN = 50 * 1024 * 1024   # 50 MB
TOTAL_PACKAGE_SIZE_CRIT = 200 * 1024 * 1024  # 200 MB

# Maximum seconds to spend scanning a single file's contents for secrets.
# Prevents ReDoS-style hangs on pathological minified artifacts. Configurable
# via content_scan_timeout_secs in .tenter.json.
CONTENT_SCAN_TIMEOUT_SECS = 5.0


# ─── Scanning Engine ─────────────────────────────────────────────────────────

class PublishGuard:
    """Core scanning engine. Examines package artifacts for security issues."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.allowlist = set(self.config.get("allowlist", []))
        self.size_limit_single = self.config.get(
            "size_limit_single_file_bytes", SINGLE_FILE_SIZE_CRIT
        )
        self.size_limit_total = self.config.get(
            "size_limit_total_bytes", TOTAL_PACKAGE_SIZE_CRIT
        )
        self.content_scan_timeout = self.config.get(
            "content_scan_timeout_secs", CONTENT_SCAN_TIMEOUT_SECS
        )

    def scan_directory(self, path: str, package_type: str = "generic") -> ScanResult:
        """Scan a directory as if it were the contents of a package."""
        root = Path(path)
        files = []
        total_size = 0

        for fp in root.rglob("*"):
            if fp.is_file():
                rel = str(fp.relative_to(root))
                size = fp.stat().st_size
                files.append((rel, size, fp))
                total_size += size

        result = ScanResult(
            package_type=package_type,
            package_path=str(path),
            total_files=len(files),
            total_size_bytes=total_size,
        )

        self._check_total_size(result, total_size)
        for rel_path, size, full_path in files:
            if self._is_allowlisted(rel_path):
                continue
            self._check_file(result, rel_path, size, full_path)

        return result

    def scan_npm_tarball(self, path: str) -> ScanResult:
        """Scan an npm .tgz package tarball."""
        return self._scan_tarball(path, "npm")

    def scan_npm_dry_run(self, project_dir: str) -> ScanResult:
        """Run npm pack --dry-run and scan the reported file list."""
        result = ScanResult(
            package_type="npm",
            package_path=project_dir,
            total_files=0,
            total_size_bytes=0,
        )

        try:
            proc = subprocess.run(
                ["npm", "pack", "--dry-run", "--json"],
                capture_output=True, text=True, cwd=project_dir, timeout=60
            )
            if proc.returncode != 0:
                # Try without --json
                proc = subprocess.run(
                    ["npm", "pack", "--dry-run"],
                    capture_output=True, text=True, cwd=project_dir, timeout=60
                )
                files = self._parse_npm_dry_run_text(proc.stdout + proc.stderr)
            else:
                files = self._parse_npm_dry_run_json(proc.stdout)
        except FileNotFoundError:
            result.findings.append(Finding(
                rule_id="NPM-001",
                severity=Severity.INFO,
                file_path="",
                message="npm not found — falling back to directory scan",
            ))
            return self.scan_directory(project_dir, "npm")
        except subprocess.TimeoutExpired:
            result.findings.append(Finding(
                rule_id="NPM-002",
                severity=Severity.MEDIUM,
                file_path="",
                message="npm pack --dry-run timed out after 60s",
            ))
            return result

        result.total_files = len(files)
        project_root = Path(project_dir)

        for rel_path in files:
            if self._is_allowlisted(rel_path):
                continue
            full_path = project_root / rel_path
            size = full_path.stat().st_size if full_path.exists() else 0
            result.total_size_bytes += size
            self._check_file(result, rel_path, size, full_path if full_path.exists() else None)

        self._check_total_size(result, result.total_size_bytes)
        return result

    def scan_pip_sdist(self, path: str) -> ScanResult:
        """Scan a pip sdist (.tar.gz) or wheel (.whl)."""
        if path.endswith(".whl"):
            return self._scan_zipfile(path, "pip")
        return self._scan_tarball(path, "pip")

    def scan_cargo_crate(self, path: str) -> ScanResult:
        """Scan a cargo .crate file."""
        return self._scan_tarball(path, "cargo")

    # ── Internal scanning methods ────────────────────────────────────────

    def _scan_tarball(self, path: str, pkg_type: str) -> ScanResult:
        result = ScanResult(
            package_type=pkg_type,
            package_path=path,
            total_files=0,
            total_size_bytes=0,
        )

        try:
            with tarfile.open(path, "r:*") as tar:
                members = [m for m in tar.getmembers() if m.isfile()]
                result.total_files = len(members)
                result.total_size_bytes = sum(m.size for m in members)

                self._check_total_size(result, result.total_size_bytes)

                for member in members:
                    rel_path = member.name
                    # Strip leading package/ or package-version/ prefix
                    parts = rel_path.split("/", 1)
                    if len(parts) > 1:
                        rel_path = parts[1]

                    if self._is_allowlisted(rel_path):
                        continue

                    # Extract to temp for content scanning
                    with tempfile.TemporaryDirectory() as tmpdir:
                        tar.extract(member, tmpdir, filter="data")
                        extracted = Path(tmpdir) / member.name
                        self._check_file(result, rel_path, member.size, extracted)

        except (tarfile.TarError, OSError) as e:
            result.findings.append(Finding(
                rule_id="PKG-001",
                severity=Severity.HIGH,
                file_path=path,
                message=f"Failed to read tarball: {e}",
            ))

        return result

    def _scan_zipfile(self, path: str, pkg_type: str) -> ScanResult:
        result = ScanResult(
            package_type=pkg_type,
            package_path=path,
            total_files=0,
            total_size_bytes=0,
        )

        try:
            with zipfile.ZipFile(path, "r") as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                result.total_files = len(infos)
                result.total_size_bytes = sum(i.file_size for i in infos)

                self._check_total_size(result, result.total_size_bytes)

                for info in infos:
                    if self._is_allowlisted(info.filename):
                        continue

                    with tempfile.TemporaryDirectory() as tmpdir:
                        # Path traversal protection (parity with tar filter="data")
                        target = Path(tmpdir).resolve() / info.filename
                        if not str(target).startswith(str(Path(tmpdir).resolve())):
                            result.findings.append(Finding(
                                rule_id="PKG-003",
                                severity=Severity.CRITICAL,
                                file_path=info.filename,
                                message="Zip path traversal detected",
                                detail=f"Entry attempts to escape extraction directory: {info.filename}",
                            ))
                            continue
                        zf.extract(info, tmpdir)
                        extracted = Path(tmpdir) / info.filename
                        self._check_file(result, info.filename, info.file_size, extracted)

        except (zipfile.BadZipFile, OSError) as e:
            result.findings.append(Finding(
                rule_id="PKG-002",
                severity=Severity.HIGH,
                file_path=path,
                message=f"Failed to read zip: {e}",
            ))

        return result

    def _check_file(self, result: ScanResult, rel_path: str, size: int,
                     full_path: Optional[Path]):
        """Run all checks against a single file."""

        # Rule: Source map files
        lower = rel_path.lower()
        if any(lower.endswith(ext) for ext in SOURCE_MAP_EXTENSIONS):
            result.findings.append(Finding(
                rule_id="MAP-001",
                severity=Severity.CRITICAL,
                file_path=rel_path,
                message="Source map file detected in package",
                detail=(
                    "Source maps expose original source code. This is the exact "
                    "vulnerability class that leaked Claude Code's 512K-line codebase."
                ),
            ))

        # Rule: sourceMappingURL references in JS/CSS
        if full_path and lower.endswith((".js", ".mjs", ".cjs", ".css")) and size < 100 * 1024 * 1024:
            try:
                content = full_path.read_bytes()
                match = SOURCE_MAP_URL_PATTERN.search(content[-4096:])  # Check tail
                if match:
                    url = match.group(1).decode("utf-8", errors="replace")
                    # External URLs are higher risk than inline data URIs
                    sev = Severity.CRITICAL if url.startswith(("http", "//")) else Severity.HIGH
                    result.findings.append(Finding(
                        rule_id="MAP-002",
                        severity=sev,
                        file_path=rel_path,
                        message=f"sourceMappingURL reference found",
                        detail=f"Points to: {url[:200]}",
                    ))
            except OSError:
                pass

        # Rule: Debug artifacts
        for pattern in DEBUG_ARTIFACT_PATTERNS:
            if self._glob_match(rel_path, pattern):
                if "MAP-001" not in [f.rule_id for f in result.findings if f.file_path == rel_path]:
                    result.findings.append(Finding(
                        rule_id="DBG-001",
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        message="Debug artifact detected in package",
                    ))
                break

        # Rule: Sensitive files
        for pattern in SENSITIVE_FILE_PATTERNS:
            basename = os.path.basename(rel_path)
            if self._glob_match(rel_path, pattern) or fnmatch.fnmatch(basename, pattern):
                result.findings.append(Finding(
                    rule_id="SEC-001",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    message="Sensitive file detected in package",
                    detail=f"Matched pattern: {pattern}",
                ))
                break

        # Rule: Internal artifacts
        for pattern in INTERNAL_ARTIFACT_PATTERNS:
            if self._glob_match(rel_path, pattern):
                result.findings.append(Finding(
                    rule_id="INT-001",
                    severity=Severity.MEDIUM,
                    file_path=rel_path,
                    message="Internal/development artifact detected in package",
                    detail=f"Matched pattern: {pattern}",
                ))
                break

        # Rule: File size anomalies
        if size > self.size_limit_single:
            result.findings.append(Finding(
                rule_id="SIZE-001",
                severity=Severity.CRITICAL,
                file_path=rel_path,
                message=f"Anomalously large file: {size / (1024*1024):.1f} MB",
                detail=(
                    f"Exceeds {self.size_limit_single / (1024*1024):.0f} MB threshold. "
                    "The Claude Code source map that leaked was 59.8 MB."
                ),
            ))
        elif size > SINGLE_FILE_SIZE_WARN:
            result.findings.append(Finding(
                rule_id="SIZE-002",
                severity=Severity.MEDIUM,
                file_path=rel_path,
                message=f"Large file: {size / (1024*1024):.1f} MB",
            ))

        # Rule: Secret patterns in file content.
        #
        # ReDoS mitigations applied here:
        #   1. Files >50MB are already limited to a 2MB head+tail window.
        #   2. search() short-circuits on the first match per pattern — no need
        #      to exhaust the whole file once a secret is found.
        #   3. A per-file time budget (self.content_scan_timeout) is enforced
        #      across all patterns. If it fires, remaining patterns are skipped
        #      and a SEC-003 MEDIUM advisory is emitted so the event is never
        #      silently dropped.
        if full_path:
            try:
                if size <= 50 * 1024 * 1024:
                    # Full scan for files up to 50MB
                    content = full_path.read_bytes()
                else:
                    # For files >50MB, scan first and last 1MB
                    # (secrets cluster in headers, configs, and appended data)
                    with open(full_path, "rb") as f:
                        head = f.read(1024 * 1024)
                        f.seek(max(0, size - 1024 * 1024))
                        tail = f.read(1024 * 1024)
                    content = head + tail

                scan_start = time.monotonic()
                timed_out = False

                for pattern, description in SECRET_PATTERNS:
                    if time.monotonic() - scan_start > self.content_scan_timeout:
                        timed_out = True
                        break
                    if pattern.search(content):
                        result.findings.append(Finding(
                            rule_id="SEC-002",
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            message=f"Potential secret detected: {description}",
                            detail="Value redacted.",
                        ))

                if timed_out:
                    result.findings.append(Finding(
                        rule_id="SEC-003",
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        message="Secret scan timed out — manual review recommended",
                        detail=(
                            f"Content scan exceeded {self.content_scan_timeout:.0f}s budget. "
                            "Not all patterns were checked. Review file contents manually."
                        ),
                    ))
            except OSError:
                pass

    def _check_total_size(self, result: ScanResult, total_bytes: int):
        if total_bytes > self.size_limit_total:
            result.findings.append(Finding(
                rule_id="SIZE-003",
                severity=Severity.HIGH,
                file_path="(total package)",
                message=f"Package size {total_bytes / (1024*1024):.1f} MB exceeds threshold",
            ))
        elif total_bytes > TOTAL_PACKAGE_SIZE_WARN:
            result.findings.append(Finding(
                rule_id="SIZE-004",
                severity=Severity.MEDIUM,
                file_path="(total package)",
                message=f"Package is large: {total_bytes / (1024*1024):.1f} MB",
            ))

    @staticmethod
    def _glob_match(rel_path: str, pattern: str) -> bool:
        """Match a relative path against a pattern, supporting ** for recursive dirs."""
        # Direct fnmatch first
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        if fnmatch.fnmatch(rel_path.lower(), pattern.lower()):
            return True
        # Handle ** prefix: strip **/ and match against the path or any suffix
        if pattern.startswith("**/"):
            suffix_pattern = pattern[3:]
            # Match against basename or any sub-path
            if fnmatch.fnmatch(rel_path, suffix_pattern):
                return True
            if fnmatch.fnmatch(os.path.basename(rel_path), suffix_pattern):
                return True
            # Try matching against each possible sub-path
            parts = rel_path.replace("\\", "/").split("/")
            for i in range(len(parts)):
                sub = "/".join(parts[i:])
                if fnmatch.fnmatch(sub, suffix_pattern):
                    return True
        # Handle ** suffix: strip trailing /** and match the directory portion
        if pattern.endswith("/**"):
            dir_pattern = pattern[:-3]
            path_dir = rel_path.replace("\\", "/")
            if dir_pattern.startswith("**/"):
                dir_pattern = dir_pattern[3:]
            parts = path_dir.split("/")
            for part in parts[:-1]:  # Check directory components
                if fnmatch.fnmatch(part, dir_pattern):
                    return True
            if fnmatch.fnmatch(path_dir, dir_pattern + "/*"):
                return True
        return False

    def _is_allowlisted(self, rel_path: str) -> bool:
        for pattern in self.allowlist:
            if self._glob_match(rel_path, pattern):
                return True
        return False

    def _parse_npm_dry_run_json(self, output: str) -> list:
        try:
            data = json.loads(output)
            if isinstance(data, list) and len(data) > 0:
                return [f.get("path", "") for f in data[0].get("files", [])]
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
        return []

    def _parse_npm_dry_run_text(self, output: str) -> list:
        files = []
        for line in output.strip().split("\n"):
            line = line.strip()
            # npm pack --dry-run outputs lines like "npm notice 123B  path/to/file"
            if line and not line.startswith("npm notice"):
                files.append(line)
            elif "npm notice" in line:
                parts = line.split()
                # Last element is typically the file path
                if len(parts) >= 4:
                    candidate = parts[-1]
                    if "/" in candidate or "." in candidate:
                        files.append(candidate)
        return files


# ─── Config Loading ──────────────────────────────────────────────────────────

def load_config(config_path: Optional[str] = None) -> dict:
    """Load config from .tenter.json or specified path."""
    if config_path:
        p = Path(config_path)
    else:
        # Search upward for config file
        candidates = [
            ".tenter.json",
            ".tenter.yaml",
            ".publishguardrc",
        ]
        p = None
        cwd = Path.cwd()
        for candidate in candidates:
            check = cwd / candidate
            if check.exists():
                p = check
                break

    if p and p.exists():
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Failed to load config from {p}: {e}", file=sys.stderr)

    return {}


# ─── Output Formatters ───────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

def format_human(result: ScanResult, use_color: bool = True) -> str:
    """Format scan results for human consumption."""
    lines = []
    c = use_color

    def col(code, text):
        return f"{code}{text}{RESET}" if c else text

    lines.append("")
    lines.append(col(BOLD, "═══ tenter scan results ═══"))
    lines.append(f"  Package type: {result.package_type}")
    lines.append(f"  Path: {result.package_path}")
    lines.append(f"  Files: {result.total_files}")
    lines.append(f"  Size: {result.total_size_bytes / 1024:.1f} KB "
                 f"({result.total_size_bytes / (1024*1024):.2f} MB)")
    lines.append("")

    if not result.findings:
        lines.append(col("\033[92m", "  ✓ No issues found. Safe to publish."))
        lines.append("")
        return "\n".join(lines)

    # Group by severity
    by_severity = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        lines.append(col(sev.color if c else "", f"  ┌─ {sev.value} ({len(findings)})"))
        for f in findings:
            icon = "✖" if sev in (Severity.CRITICAL, Severity.HIGH) else "⚠" if sev == Severity.MEDIUM else "ℹ"
            lines.append(col(sev.color if c else "", f"  │ {icon} [{f.rule_id}] {f.file_path}"))
            lines.append(f"  │   {f.message}")
            if f.detail:
                lines.append(col(DIM, f"  │   {f.detail}"))
        lines.append(f"  └{'─' * 60}")
        lines.append("")

    # Summary
    total = len(result.findings)
    crit = len(by_severity.get(Severity.CRITICAL, []))
    high = len(by_severity.get(Severity.HIGH, []))

    if crit > 0 or high > 0:
        lines.append(col("\033[91m", f"  ✖ BLOCKED: {total} finding(s) — "
                        f"{crit} critical, {high} high. DO NOT PUBLISH."))
    else:
        lines.append(col("\033[93m", f"  ⚠ {total} finding(s). Review before publishing."))

    lines.append("")
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def format_sarif(result: ScanResult) -> str:
    """Format as SARIF v2.1.0 for CI integration (GitHub, GitLab, etc.)."""
    rules = {}
    sarif_results = []

    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.message},
            }

        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        sarif_results.append({
            "ruleId": f.rule_id,
            "level": severity_map[f.severity],
            "message": {
                "text": f"{f.message}. {f.detail}" if f.detail else f.message
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file_path,
                    }
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "tenter",
                    "version": __version__,
                    "informationUri": "https://github.com/goweft/tenter",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }

    return json.dumps(sarif, indent=2)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenter",
        description=(
            "Pre-publish artifact integrity scanner. "
            "Detects source maps, debug artifacts, secrets, and other "
            "sensitive files before they ship in your package."
        ),
        epilog="Born from the Claude Code npm source map leak (2026-03-31).",
    )

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    sub = parser.add_subparsers(dest="command", help="Scan mode")

    # scan subcommand
    scan = sub.add_parser("scan", help="Scan a package artifact or directory")
    scan.add_argument("target", help="Path to package tarball, wheel, or directory")
    scan.add_argument(
        "--type", "-t", dest="pkg_type",
        choices=["npm", "pip", "cargo", "auto"],
        default="auto",
        help="Package type (default: auto-detect)",
    )
    scan.add_argument(
        "--format", "-f", dest="output_format",
        choices=["human", "json", "sarif"],
        default="human",
        help="Output format (default: human)",
    )
    scan.add_argument(
        "--config", "-c",
        help="Path to config file (default: .tenter.json)",
    )
    scan.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    scan.add_argument(
        "--fail-on", dest="fail_on",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Minimum severity to cause non-zero exit (default: high)",
    )

    # npm-check subcommand
    npm_check = sub.add_parser(
        "npm-check",
        help="Run npm pack --dry-run and scan results",
    )
    npm_check.add_argument(
        "project_dir", nargs="?", default=".",
        help="Path to npm project directory (default: .)",
    )
    npm_check.add_argument(
        "--format", "-f", dest="output_format",
        choices=["human", "json", "sarif"],
        default="human",
    )
    npm_check.add_argument("--config", "-c")
    npm_check.add_argument("--no-color", action="store_true")
    npm_check.add_argument(
        "--fail-on", dest="fail_on",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
    )

    # init subcommand
    sub.add_parser("init", help="Create a default .tenter.json config")

    return parser


def detect_package_type(path: str) -> str:
    """Auto-detect package type from file extension or directory contents."""
    p = Path(path)
    if p.is_dir():
        if (p / "package.json").exists():
            return "npm"
        elif (p / "setup.py").exists() or (p / "pyproject.toml").exists():
            return "pip"
        elif (p / "Cargo.toml").exists():
            return "cargo"
        return "generic"

    name = p.name.lower()
    if name.endswith(".tgz") or name.endswith(".tar.gz"):
        if "node" in name or "npm" in name:
            return "npm"
        return "npm"  # npm tarballs are more common
    elif name.endswith(".whl"):
        return "pip"
    elif name.endswith(".crate"):
        return "cargo"
    return "generic"


def create_default_config():
    """Write a default .tenter.json."""
    config = {
        "$schema": "https://github.com/goweft/tenter/blob/main/schema.json",
        "allowlist": [],
        "size_limit_single_file_bytes": SINGLE_FILE_SIZE_CRIT,
        "size_limit_total_bytes": TOTAL_PACKAGE_SIZE_CRIT,
        "content_scan_timeout_secs": CONTENT_SCAN_TIMEOUT_SECS,
        "extra_sensitive_patterns": [],
        "extra_debug_patterns": [],
    }

    out = Path(".tenter.json")
    if out.exists():
        print(f"Config already exists at {out}", file=sys.stderr)
        return 1

    out.write_text(json.dumps(config, indent=2) + "\n")
    print(f"Created {out}")
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "init":
        return create_default_config()

    # Load config
    config = load_config(getattr(args, "config", None))
    guard = PublishGuard(config)

    # Determine fail threshold
    fail_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    fail_threshold = fail_map[args.fail_on]

    # Run scan
    if args.command == "npm-check":
        result = guard.scan_npm_dry_run(args.project_dir)
    elif args.command == "scan":
        target = Path(args.target)
        pkg_type = args.pkg_type
        if pkg_type == "auto":
            pkg_type = detect_package_type(str(target))

        if target.is_dir():
            result = guard.scan_directory(str(target), pkg_type)
        elif str(target).endswith(".whl"):
            result = guard.scan_pip_sdist(str(target))
        elif str(target).endswith(".crate"):
            result = guard.scan_cargo_crate(str(target))
        else:
            result = guard.scan_npm_tarball(str(target))
    else:
        parser.print_help()
        return 0

    # Format output
    use_color = not getattr(args, "no_color", False) and sys.stdout.isatty()
    if args.output_format == "json":
        print(format_json(result))
    elif args.output_format == "sarif":
        print(format_sarif(result))
    else:
        print(format_human(result, use_color=use_color))

    # Determine exit code
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    threshold_idx = severity_order.index(fail_threshold)
    blocking_severities = set(severity_order[:threshold_idx + 1])

    if any(f.severity in blocking_severities for f in result.findings):
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
