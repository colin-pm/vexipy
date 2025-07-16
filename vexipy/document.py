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
    """

    context: str = Field(alias="@context")
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
        """Convert dict input to tuple of tuples"""
        return None if v is None else tuple(v)

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        """Serializes timestamp parameter as a ISO 8601 string"""
        return value.isoformat()

    def update(self, **kwargs: Any) -> "Document":
        obj = self.model_dump()
        obj.update(
            kwargs if "timestamp" in kwargs else (kwargs | {"timestamp": utc_now()})
        )
        return Document(**obj)

    def append_statements(self, statement: Statement) -> "Document":
        return self.update(
            statements=self.statements + (statement,)
            if self.statements
            else (statement,)
        )

    def extend_statements(self, statements: Iterable[Statement]) -> "Document":
        return self.update(
            statements=self.statements + tuple(statements)
            if self.statements
            else tuple(statements)
        )

    def to_json(self, **kwargs: Any) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Document":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
