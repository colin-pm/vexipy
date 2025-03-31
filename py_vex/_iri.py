from typing import Annotated

from pydantic.functional_validators import AfterValidator
from rfc3987 import match


def check_iri(iri: str) -> str:
    """Validate that a string is a valid IRI."""
    if not match(iri, rule="IRI"):
        raise ValueError(f'Invalid IRI: "{iri}"')
    return iri


Iri = Annotated[str, AfterValidator(check_iri)]
