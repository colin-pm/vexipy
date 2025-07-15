# py-vex

![py-vex logo](files/logo.png)

A Python implementation of the [OpenVEX specification][]

## Installing

TODO - Publish on PyPI

## Example Usage

```python
from py_vex import Component, Document, Statement, Vulnerability

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

[OpenVEX specification]: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
