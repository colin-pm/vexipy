"""
Defines models for software components and subcomponents, including identifiers and hashes.
"""

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

    :param id: Optional IRI identifying the component to make it externally referenceable.
    :param identifiers: A map of software identifiers where the key is the type and the value the identifier. OpenVEX favors the use of purl but others are recognized.
    :param hashes: Map of cryptographic hashes of the component. The key is the algorithm name based on the Hash Function Textual Names from IANA.
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
        """
        Converts a mapping to a read-only MappingProxyType.

        :param v: Mapping of strings or None.
        :return: Read-only mapping or None if not provided.
        """
        if v is None:
            return None
        return MappingProxyType(v)

    @field_validator("identifiers", mode="after")
    @classmethod
    def identifiers_valid(
        cls, value: Optional[MappingProxyType[str, str]]
    ) -> Optional[MappingProxyType[str, str]]:
        """
        Validates that all identifier keys are valid.

        :param value: Read-only mapping of identifiers.
        :raises ValueError: If invalid identifier keys are present.
        :return: Validated mapping or None.
        """
        if value is None:
            return value
        if not IDENTIFIER_KEYS.issuperset(value.keys()):
            raise ValueError(
                f'"{", ".join(value.keys() - IDENTIFIER_KEYS)}" are not valid'
                " identifiers"
            )
        return value

    @field_validator("hashes", mode="after")
    @classmethod
    def hashes_valid(
        cls, value: Optional[MappingProxyType[str, str]]
    ) -> Optional[MappingProxyType[str, str]]:
        """
        Validates that all hash keys are valid.

        :param value: Read-only mapping of hashes.
        :raises ValueError: If invalid hash keys are present.
        :return: Validated mapping or None.
        """
        if value is None:
            return value
        if not HASH_KEYS.issuperset(value.keys()):
            raise ValueError(
                f'"{", ".join(value.keys() - HASH_KEYS)}" are not valid hashes'
            )
        return value

    def update(self, **kwargs: Any) -> "Product":
        """
        Returns a new Component instance with updated fields.

        :param kwargs: Fields to update in the model.
        :return: Updated Component instance.
        """
        obj = self.model_dump()
        obj.update(kwargs)
        return Product(**obj)

    def to_json(self, **kwargs: Any) -> str:
        """
        Serializes the Subcomponent model to a JSON string.

        :param kwargs: Additional keyword arguments for serialization.
        :return: JSON string representation of the model.
        """
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Subcomponent":
        """
        Creates a Subcomponent instance from a JSON string.

        :param json_string: JSON string to deserialize.
        :return: Subcomponent instance.
        """
        return cls.model_validate_json(json_string)


class Product(Subcomponent):
    """
    A logical unit representing a piece of software. The concept is intentionally broad to allow for a wide variety of use cases but generally speaking, anything that can be described in a Software Bill of Materials (SBOM) can be thought of as a product.

    :param id: Optional IRI identifying the component to make it externally referenceable.
    :param identifiers: A map of software identifiers where the key is the type and the value the identifier. OpenVEX favors the use of purl but others are recognized.
    :param hashes: Map of cryptographic hashes of the component. The key is the algorithm name based on the Hash Function Textual Names from IANA.
    :param subcomponents: Tuple of subcomponents included in the component.
    """

    subcomponents: Optional[Tuple["Subcomponent", ...]] = Field(default=None)

    @field_validator("subcomponents", mode="before")
    @classmethod
    def convert_to_tuple(
        cls, v: Optional[Iterable["Subcomponent"]]
    ) -> Optional[Tuple["Subcomponent", ...]]:
        """
        Converts an iterable of subcomponents to a tuple.

        :param v: Iterable of Subcomponent objects or None.
        :return: Tuple of Subcomponent objects or None if not provided.
        """
        return None if v is None else tuple(v)

    def append_subcomponents(self, subcomponent: "Subcomponent") -> "Product":
        """
        Returns a new Component with the given subcomponent appended.

        :param subcomponent: Subcomponent to append.
        :return: Updated Component instance.
        """
        return self.update(
            subcomponents=(
                self.subcomponents + (subcomponent,)
                if self.subcomponents
                else (subcomponent,)
            )
        )

    def extend_subcomponents(
        self, subcomponents: Iterable["Subcomponent"]
    ) -> "Product":
        """
        Returns a new Component with the given collection of subcomponents extended to the subcomponents tuple.

        :param subcomponents: Iterable of Subcomponent objects to extend.
        :return: Updated Component instance.
        """
        return self.update(
            subcomponents=(
                self.subcomponents + tuple(subcomponents)
                if self.subcomponents
                else subcomponents
            )
        )
