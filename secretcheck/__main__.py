import sys
from pathlib import Path

from .scanner import scan_directory

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m secretcheck <directory>")
        return

    directory = Path(sys.argv[1])
    try:
        findings = scan_directory(directory)
    except (FileNotFoundError, NotADirectoryError) as error:
        print(f"Error: {error}")
        return

    print("SecretCheck - Scan report\n")

    for finding in findings:
        print(
            f"[HIGH] {finding['file']}:{finding['line']} "
            f"- {finding['type']}"
        )

    print(f"\n{len(findings)} potential secrets detected.")


if __name__ == "__main__":
    main()