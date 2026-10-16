#!/usr/bin/env python3
"""
NexusEdge Automated Secret & Entropy Scanner
Enforces OWASP ASVS V2 & NIST SSDF PW.1.2:
Zero Secrets in Source Code, Documentation, or Build Trees.
"""

import os
import re
import subprocess
import sys

# High-risk secret detection regex patterns
SECRET_PATTERNS = [
    (
        "Private Cryptographic Key",
        re.compile(r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?(?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED|PRIVATE)\s+(?:PRIVATE\s+)?KEY", re.IGNORECASE),
    ),
    (
        "AWS Access Key ID",
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ),
    (
        "GitHub Personal/OAuth Access Token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
    ),
    (
        "Slack Bot/User Token",
        re.compile(r"xox(?:a|b|p|r|s)-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
    ),
    (
        "Google Cloud Platform API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    (
        "Stripe Live API Key",
        re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24}"),
    ),
    (
        "Hardcoded High-Entropy Password/Secret Assignment",
        re.compile(
            r"""(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|password)\s*[:=]\s*["'](?![$%{\[])[a-zA-Z0-9+/=_\-]{24,}["']""",
            re.IGNORECASE,
        ),
    ),
]

# Paths and files that are explicitly allowed to contain mock/dummy tokens or schemas
ALLOWLIST_PATTERNS = [
    re.compile(r"\.git[\\/]"),
    re.compile(r"\.env\.example$"),
    re.compile(r"package-lock\.json$"),
    re.compile(r"Cargo\.lock$"),
    re.compile(r"go\.sum$"),
    re.compile(r"[\\/]test[s]?[\\/]"),
    re.compile(r"_test\.go$"),
    re.compile(r"\.test\.js$"),
    re.compile(r"test_[a-zA-Z0-9_]+\.py$"),
    re.compile(r"tools[\\/]ci[\\/]scan-secrets\.py$"),
    re.compile(r"scratch[\\/]"),
    re.compile(r"\.user_uploaded[\\/]"),
]


def is_allowlisted(filepath: str) -> bool:
    norm = filepath.replace("/", os.sep).replace("\\", os.sep)
    for pat in ALLOWLIST_PATTERNS:
        if pat.search(norm):
            return True
    return False


def get_git_tracked_files(repo_root: str):
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception as e:
        print(f"Warning: git ls-files failed ({e}), falling back to os.walk...")
        files = []
        for root, _, filenames in os.walk(repo_root):
            if ".git" in root:
                continue
            for f in filenames:
                rel = os.path.relpath(os.path.join(root, f), repo_root)
                files.append(rel)
        return files


def scan_file(repo_root: str, rel_path: str):
    if is_allowlisted(rel_path):
        return []

    full_path = os.path.join(repo_root, rel_path)
    if not os.path.isfile(full_path):
        return []

    findings = []
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                # Ignore comment lines in shell/python/yaml
                stripped = line.strip()
                if stripped.startswith("#") and "example" in stripped.lower():
                    continue

                for label, pattern in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        matched_val = match.group(0)
                        # Filter out common placeholders
                        if any(
                            dummy in matched_val.lower()
                            for dummy in ["example", "dummy", "placeholder", "xxx", "your_", "replace_me"]
                        ):
                            continue
                        findings.append((rel_path, line_no, label, matched_val[:8] + "..." + matched_val[-4:] if len(matched_val) > 16 else "[REDACTED]"))
    except Exception as e:
        print(f"Warning: Could not read {rel_path}: {e}")

    return findings


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))

    tracked_files = get_git_tracked_files(repo_root)
    total_scanned = 0
    all_findings = []

    for fpath in tracked_files:
        if not is_allowlisted(fpath):
            total_scanned += 1
            findings = scan_file(repo_root, fpath)
            if findings:
                all_findings.extend(findings)

    print(f"Secret Scanner: Inspected {total_scanned} tracked non-test files.")

    if all_findings:
        print("\n[CRITICAL SECURITY ALERT] Potentially leaked secrets or private keys detected:")
        for path, line, label, snippet in all_findings:
            print(f"  - {path}:{line} [{label}] -> {snippet}")
        print("\nFailure: Refusing to proceed with unencrypted secrets in source tree (OWASP ASVS V2).")
        sys.exit(1)

    print("Secret Scanner: 100% clean. Zero committed credentials detected.")
    sys.exit(0)


if __name__ == "__main__":
    main()
