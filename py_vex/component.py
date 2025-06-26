from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from py_vex._iri import Iri

IDENTIFIER_KEYS = {
    "purl",
    "cpe22",
    "cpe23",
}

HASH_KEYS = {
    "md5",
    "sha1",
    "sha-256",
    "sha-384",
    "sha-512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "blake2s-256",
    "blake2b-256",
    "blake2b-512",
}


class Subcomponent(BaseModel):
    """
    A logical unit representing a piece of software.
    The concept is intentionally broad to allow for a wide variety of use cases
    but generally speaking, anything that can be described in a Software Bill of
    Materials (SBOM) can be thought of as a product.
    """

    id: Optional[Iri] = Field(alias="@id", default=None)
    identifiers: Optional[Dict[str, str]] = None
    hashes: Optional[Dict[str, str]] = None

    model_config = ConfigDict(populate_by_name=True)

    @field_validator("identifiers", mode="after")
    @classmethod
    def identifiers_valid(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not IDENTIFIER_KEYS.issuperset(value.keys()):
            raise ValueError(
                f'"{", ".join(value.keys() - IDENTIFIER_KEYS)}" are not valid identifiers'
            )
        return value

    @field_validator("hashes", mode="after")
    @classmethod
    def hashes_valid(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not HASH_KEYS.issuperset(value.keys()):
            raise ValueError(
                f'"{", ".join(value.keys() - HASH_KEYS)}" are not valid hashes'
            )
        return value

    def to_json(self, **kwargs: Any) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Subcomponent":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)


class Component(Subcomponent):
    """
    Any components possibly included in the product where the vulnerability
    originates. The subcomponents SHOULD also list software identifiers and they
    SHOULD also be listed in the product SBOM. subcomponents will most often be
    one or more of the product's dependencies.
    """

    subcomponents: Optional[List["Subcomponent"]] = None

    @classmethod
    def from_json(cls, json_string: str) -> "Component":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
