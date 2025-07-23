# vexipy

[![Validate](https://github.com/colin-pm/vexipy/actions/workflows/validate.yaml/badge.svg)](https://github.com/colin-pm/vexipy/actions/workflows/validate.yaml)
![Codecov](https://img.shields.io/codecov/c/github/colin-pm/vexipy)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/colin-pm/vexipy/badge)](https://scorecard.dev/viewer/?uri=github.com/colin-pm/vexipy)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10913/badge)](https://www.bestpractices.dev/projects/10913)
[![CodeQL](https://github.com/colin-pm/vexipy/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/colin-pm/vexipy/actions/workflows/github-code-scanning/codeql)


![py-vex logo](files/logo.png)

A Python implementation of the [OpenVEX specification][].

This library aims to provide a simple-to-use API for creating, validating, and modifying OpenVEX data.

## Installing

```bash
python3 -m pip install vexipy
```

## Example Usage

```python
from vexipy import Component, Document, Statement, Vulnerability

vulnerability = Vulnerability(
    id="https://nvd.nist.gov/vuln/detail/CVE-2019-17571",
    name="CVE-2019-17571",
    description="The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
    aliases=[
        "GHSA-2qrg-x229-3v8q",
        "openSUSE-SU-2020:0051-1",
        "SNYK-RHEL7-LOG4J-1472071",
        "DSA-4686-1",
        "USN-4495",
        "DLA-2065-1",
    ],
)
print(vulnerability.to_json())

document = Document.from_json(
    """
    {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Wolfi J Inkinson",
        "role": "Document Creator",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": "1",
        "statements": [
            {
            "vulnerability": {
                "name": "CVE-2014-123456"
            },
            "products": [
                {"@id": "pkg:apk/distro/git@2.39.0-r1?arch=armv7"},
                {"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}
            ],
            "status": "fixed"
            }
        ]
    }
    """
)

statement = Statement(
    vulnerability=Vulnerability(name="CVE-2014-123456"),
    status="fixed",
)

component = Component(
    identifiers={"purl": "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie"},
    hashes={"md5": "a2eec1a40a5315b1e2ff273aa747504b"},
)

statement = statement.update(products=[component])

document = document.append_statements(statement)
```

## Contributing

We welcome contributions to this project! To contribute, please follow these guidelines:

## How to Contribute

1. **Fork the repository** - Create a fork of this repository to your GitHub account
2. **Create a feature branch** - Make your changes in a new branch off of `main`
3. **Make your changes** - Implement your feature or bug fix
4. **Submit a Pull Request** - Open a PR from your fork's branch to our `main` branch

## Requirements

### Code Quality Standards

- **Tests must pass** - All existing tests must continue to pass
- **Test coverage** - New code is expected to include appropriate test coverage
- **PEP standards** - Code must follow Python Enhancement Proposal (PEP) standards
- **Linting and formatting** - Code must pass all linting and formatting checks

### Development Tools

Before submitting a PR, please run the following tools locally:

```bash
# Format code
ruff format .

# Check for linting issues
ruff check .

# Sort imports
isort .

# Type checking
mypy .
```

These tools are enforced by CI and your PR will not be merged if any checks fail.

### Signed-off-by Line

All commits must include a `Signed-off-by` line. This certifies that you have the right to submit the code under the project's license and agrees to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).

To add a signed-off-by line to your commit, use the `-s` flag:

```bash
git commit -s -m "Your commit message"
```

This will automatically add a line like:
```
Signed-off-by: Your Name <your.email@example.com>
```

### Pull Request Process

- Ensure your PR has a clear title and description
- Reference any related issues in your PR description
- Make sure all commits in your PR include the signed-off-by line
- Verify that all tests pass and code meets quality standards
- Run all development tools locally before submitting
- Be prepared to address feedback and make changes if requested

## Questions?

If you have questions about contributing, please open an issue or reach out to the maintainers.

[OpenVEX specification]: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
