"""
Defines the Document model for grouping VEX statements and related metadata.
"""

from datetime import datetime
from typing import Any, Iterable, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
)

from vexipy._iri import Iri
from vexipy._util import utc_now
from vexipy.statement import Statement


class Document(BaseModel):
    """
    A data structure that groups together one or more VEX statements.

    :param context: The URL linking to the OpenVEX context definition. The URL is structured as https://openvex.dev/ns/v[version], where [version] represents the specific version number, such as v0.2.0. If the version is omitted, it defaults to v0.2.0.
    :param id: The IRI identifying the VEX document.
    :param author: Author is the identifier for the author of the VEX statement. This field should ideally be a machine readable identifier such as an IRI, email address, etc. author MUST be an individual or organization. author identity SHOULD be cryptographically associated with the signature of the VEX document or other exchange mechanism.
    :param role: role describes the role of the document author.
    :param timestamp: Timestamp defines the time at which the document was issued.
    :param last_updated: Date of last modification to the document.
    :param version: Version is the document version. It must be incremented when any content within the VEX document changes, including any VEX statements included within the VEX document.
    :param tooling: Tooling expresses how the VEX document and contained VEX statements were generated. It may specify tools or automated processes used in the document or statement generation.
    :param statements: The collection of statements to contain within the document.
    """

    context: str = Field(alias="@context", default="https://openvex.dev/ns/v0.2.0")
    id: Iri = Field(alias="@id")
    author: str
    role: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    last_updated: Optional[datetime] = None
    version: int
    tooling: Optional[str] = None
    statements: Tuple[Statement, ...] = Field(default=tuple())

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    @field_validator("statements", mode="before")
    @classmethod
    def convert_to_tuple(cls, v: Iterable[Statement]) -> Tuple[Statement, ...]:
        """
        Converts an iterable of statements to a tuple.

        :param v: Iterable of Statement objects.
        :return: Tuple of Statement objects or None if not provided.
        """
        return None if v is None else tuple(v)

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        """
        Serializes the timestamp to ISO 8601 string format.

        :param value: The datetime value to serialize.
        :return: ISO 8601 formatted string.
        """
        return value.isoformat()

    def update(self, **kwargs: Any) -> "Document":
        """
        Returns a new Document instance with updated fields and timestamp.

        If a timestamp is not provided in kwargs, the new document instance will default to the current UTC time.

        :param kwargs: Fields to update in the model.
        :return: Updated Document instance.
        """
        obj = self.model_dump()
        obj.update(
            kwargs if "timestamp" in kwargs else (kwargs | {"timestamp": utc_now()})
        )
        return Document(**obj)

    def append_statements(self, statement: Statement) -> "Document":
        """
        Returns a new Document with the given statement appended to the statements tuple.

        :param statement: Statement to append.
        :type statement: Statement
        :return: Updated Document instance.
        :rtype: Document
        """
        return self.update(
            statements=(
                self.statements + (statement,) if self.statements else (statement,)
            )
        )

    def extend_statements(self, statements: Iterable[Statement]) -> "Document":
        """
        Returns a new Document with the given collection of statements extended to the statements tuple.

        :param statements: Iterable of Statement objects to extend.
        :return: Updated Document instance.
        """
        return self.update(
            statements=(
                self.statements + tuple(statements)
                if self.statements
                else tuple(statements)
            )
        )

    def to_json(self, **kwargs: Any) -> str:
        """
        Serializes the Document model to a JSON string.

        :param kwargs: Additional keyword arguments for serialization.
        :return: JSON string representation of the model.
        """
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Document":
        """
        Creates a Document instance from a JSON string.

        :param json_string: JSON string to deserialize.
        :return: Document instance.
        """
        return cls.model_validate_json(json_string)
