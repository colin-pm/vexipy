"""
Defines the Iri type and validation for Internationalized Resource Identifiers (IRIs).
"""

from typing import Annotated

from pydantic.functional_validators import AfterValidator
from rfc3987 import match  # type: ignore


def check_iri(iri: str) -> str:
    """
    Validates that a string is a valid IRI according to RFC 3987.

    :param iri: The string to validate as an IRI.
    :raises ValueError: If the string is not a valid IRI.
    :return: The validated IRI string.
    """
    if not match(iri, rule="IRI"):
        raise ValueError(f'Invalid IRI: "{iri}"')
    return iri


Iri = Annotated[str, AfterValidator(check_iri)]
"""
Type alias for a string validated as an IRI using RFC 3987 rules.
"""
