import argparse
import logging
import re
from pathlib import Path

SECRET_PATTERNS = {
    "Hardcoded Password": (
        r"""(?i)\bpassword\s*["'][^"'\r\n]+["']"""
    ),
    "GitHub Token": (
        r"\bghp_[A-Za-z0-9]{36}\b"
    ),
    "GitLab Token": (
        r"\bglpat-[A-Za-z0-9_-]{20}\b"
    ),
    "Google API Key": (
        r"\bAIza[A-Za-z0-9_-]{35}\b"
    ),
    "AWS Access Key": (
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ),
    "Private Key": (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "Stripe Secret Key": (
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"
    ),
}

def scan_file(file_path):
    findings = []
                
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):

                for secret_type, pattern in SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, line):
                        findings.append({
                            "file": str(file_path),
                            "line": line_number,
                            "type": secret_type,
                            "match": match.group()
                        })

    except (OSError, UnicodeError) as error:
        logging.warning("Could not read %s: %s", file_path, error)

    return findings

# Accept either a single file or an entire directory
def scan_path(path):
    all_findings = []

    if path.is_file():
        files = [path]
    else:
        files = [
            file for file in path.rglob("*")
            if file.is_file()
            and not any(
                part in {".git", ".venv", "venv", "__pycache__"}
                for part in file.parts
            )
        ]

    logging.info("Found %d files to scan.", len(files))

    for file in files:
        logging.info("Scanning: %s", file)
        all_findings.extend(scan_file(file))

    return all_findings

# Display the final report
def print_report(findings):
    print("\n===== SECRET SCAN REPORT =====\n")

    if not findings:
        print("No potential secrets found.")
    else:
        for number, finding in enumerate(findings, start=1):
            print(f"Finding #{number}")
            print(f"Type: {finding['type']}")
            print(f"File: {finding['file']}")
            print(f"Line: {finding['line']}")
            print(f"Match: {finding['match']}")
            print("-" * 35)

    print(f"\nTotal findings: {len(findings)}")

# Handles CLI arguments and starts scanning
def main():
    parser = argparse.ArgumentParser(
        description="Scan files or directories for hardcoded secrets."
    )

    parser.add_argument(
        "path",
        help="File or directory to scan"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed scanning progress"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s"
    )

    target = Path(args.path)

    if not target.exists():
        parser.error("The specified path does not exist.")

    if not target.is_file() and not target.is_dir():
        parser.error("The path must be a file or directory.")

    logging.warning("Starting scan: %s", target)

    findings = scan_path(target)

    print_report(findings)

    logging.warning("Scan complete.")

if __name__ == "__main__":
    main()