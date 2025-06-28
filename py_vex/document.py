from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator
from typing_extensions import Self

from py_vex._iri import Iri
from py_vex._util import utc_now
from py_vex.statement import Statement


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
    statements: List[Statement] = []

    model_config = ConfigDict(populate_by_name=True, validate_assignment=True)

    @model_validator(mode="after")
    def update_statement_backreferences(self) -> Self:
        """Ensures each statement object references this document"""
        for statement in self.statements:
            statement._document = self
        return self

    @field_serializer("timestamp", "last_updated")
    def serialize_timestamp(self, value: datetime) -> str:
        return value.isoformat()

    def to_json(self, **kwargs: Any) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(exclude_none=True, **kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Document":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
