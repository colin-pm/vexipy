Quickstart
==========

Vexipy is a Python library for creating, validating, and modifying OpenVEX data.

Installation
------------

Install Vexipy using pip:

.. code-block:: bash

    pip install vexipy

Basic Usage
-----------

Create a VEX Document
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from vexipy import Document, Statement, StatusLabel, Vulnerability

    doc = Document(
        context="https://openvex.dev/ns/v0.2.0",
        id="https://openvex.dev/docs/example/vex-9fb3463de1b57",
        timestamp= "2023-01-08T18:02:03.647787998-06:00",
        author="Wolfi J Inkinson",
        role="Document Creator",
        version="1",
        statements=[
            Statement(
                vulnerability=Vulnerability(name="CVE-2014-123456"),
                products=[
                    {"@id": "pkg:apk/distro/git@2.39.0-r1?arch=armv7"},
                    {"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}
                ],
                status=StatusLabel.FIXED,
            )
        ]
    )

    # Serialize to JSON
    json_str = doc.to_json()
    print(json_str)

Modifying an Object
~~~~~~~~~~~~~~~~~~~

Vexipy's objects are immutable. Class instances are modified using the update method.

.. code-block:: python

    # Update the status of the statement
    doc = doc.update(author="John Smith")

The reason for immutability is to ensure that the integrity of the data is maintained, especially when dealing with complex relationships between Documents, Statements, and their underlying metadata.
Timestamps are also automatically managed by the library, so you don't need to worry about updating them manually when data is modified.

Loading from JSON
~~~~~~~~~~~~~~~~~

.. code-block:: python

    doc = Document.from_json(
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
    print(doc)


For more details, see the API documentation and examples in the repository.
