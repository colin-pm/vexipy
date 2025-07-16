from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from vexipy._iri import Iri

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
    identifiers: Optional[Dict[str, str]] = Field(default=None)
    hashes: Optional[Dict[str, str]] = Field(default=None)

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    @field_validator("identifiers", "hashes", mode="before")
    @classmethod
    def make_data_readonly(
        cls, v: Optional[Mapping[str, str]]
    ) -> Optional[MappingProxyType[str, str]]:
        if v is None:
            return None
        return MappingProxyType(v)

    @field_validator("identifiers", mode="after")
    @classmethod
    def identifiers_valid(
        cls, value: Optional[MappingProxyType[str, str]]
    ) -> Optional[MappingProxyType[str, str]]:
        if value is None:
            return value
        if not IDENTIFIER_KEYS.issuperset(value.keys()):
            raise ValueError(
                f'"{", ".join(value.keys() - IDENTIFIER_KEYS)}" are not valid identifiers'
            )
        return value

    @field_validator("hashes", mode="after")
    @classmethod
    def hashes_valid(
        cls, value: Optional[MappingProxyType[str, str]]
    ) -> Optional[MappingProxyType[str, str]]:
        if value is None:
            return value
        if not HASH_KEYS.issuperset(value.keys()):
            raise ValueError(
                f'"{", ".join(value.keys() - HASH_KEYS)}" are not valid hashes'
            )
        return value

    def update(self, **kwargs: Any) -> "Component":
        obj = self.model_dump()
        obj.update(kwargs)
        return Component(**obj)

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

    subcomponents: Optional[Tuple["Subcomponent", ...]] = Field(default=None)

    @field_validator("subcomponents", mode="before")
    @classmethod
    def convert_to_tuple(
        cls, v: Optional[Iterable["Subcomponent"]]
    ) -> Optional[Tuple["Subcomponent", ...]]:
        """Convert dict input to tuple of tuples"""
        return None if v is None else tuple(v)

    def append_subcomponents(self, subcomponent: "Subcomponent") -> "Component":
        return self.update(
            subcomponents=self.subcomponents + (subcomponent,)
            if self.subcomponents
            else (subcomponent,)
        )

    def extend_subcomponents(
        self, subcomponents: Iterable["Subcomponent"]
    ) -> "Component":
        return self.update(
            subcomponents=self.subcomponents + tuple(subcomponents)
            if self.subcomponents
            else subcomponents
        )
