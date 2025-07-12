from typing import Any, Iterable, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from py_vex._iri import Iri
from py_vex.statement import Statement


class Document(BaseModel):
    """
    A data structure that groups together one or more VEX statements.
    """

    context: str = Field(alias="@context")
    id: Iri = Field(alias="@id")
    author: str
    role: Optional[str] = None
    timestamp: str
    version: int
    tooling: Optional[str] = None
    statements: Tuple[Statement, ...] = Field(default=tuple())

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    @field_validator("statements", mode="before")
    @classmethod
    def convert_to_tuple(cls, v: Iterable[Statement]) -> Tuple[Statement, ...]:
        """Convert dict input to tuple of tuples"""
        return None if v is None else tuple(v)

    def to_json(self, **kwargs: Any) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Document":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
