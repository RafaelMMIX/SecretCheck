# SecretCheck

**Local secret scanner for developers.**

SecretCheck is a Python command-line tool that scans local project files for potential exposed secrets, such as API keys, passwords and access tokens.

It helps developers identify suspicious hardcoded credentials before sharing or publishing their code.

## Features

- Detects potential API keys, passwords and access tokens.
- Scans individual files and directories recursively.
- Ignores common directories such as `.git`, `node_modules` and `__pycache__`.
- Reports the file path, line number and detected secret type.
- Avoids displaying the detected secret values in scan results.
- Handles unreadable files without stopping the entire scan.
- Includes automated tests with pytest.

## Requirements

- Python 3.10 or newer
- pytest (for development and testing)

## Usage

From the repository root, run:

```bash
python -m secretcheck .
```

To scan a specific directory:

```bash
python -m secretcheck path/to/project
```

The report identifies potential secrets by file, line number and type.

## Running tests

Install pytest:

```bash
python -m pip install pytest
```

Run the test suite:

```bash
python -m pytest -v
```

## Limitations

SecretCheck uses regular expressions to identify suspicious patterns. It may produce false positives or miss secrets that do not match its current rules.

A detection does not prove that a credential is valid or active. Always review the results manually.

SecretCheck is not a replacement for a dedicated secret-scanning solution.

## Security and privacy

SecretCheck analyses local files and does not intentionally send source code or detected values to an external service.

Never commit real credentials, API keys or access tokens to a repository, including test files.

If a real credential has been exposed, revoke or rotate it immediately. Removing it from a file alone may not remove it from Git history.

## License

This project is distributed under the MIT License. See `LICENSE` for details.