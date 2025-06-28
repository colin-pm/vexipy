from contextlib import ExitStack, contextmanager
from datetime import datetime
from typing import Any, Iterator, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationInfo,
    field_serializer,
    model_validator,
)
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

    _auto_timestamp_last_updated: bool = PrivateAttr(default=True)

    model_config = ConfigDict(populate_by_name=True, validate_assignment=True)

    @model_validator(mode="after")
    def update_statement_backreferences(self) -> Self:
        """Ensures each statement object references this document"""
        for statement in self.statements:
            statement._document = self
        return self

    @model_validator(mode="after")
    def update_last_updated_timestamp(self, info: ValidationInfo) -> Self:
        """Updates the last_updated field if data is modified"""
        # Auto-update disabled for this statement
        if not self._auto_timestamp_last_updated:
            return self
        # Ensure the object is getting assigned and is not getting instantiated
        if info.context and info.context.get("assignment_mode"):
            self.last_updated = utc_now()
        return self

    @field_serializer("timestamp", "last_updated")
    def serialize_timestamp(self, value: datetime) -> str:
        return value.isoformat()

    @contextmanager
    def disable_last_updated(self) -> Iterator[Self]:
        """Disable updating the last_updated field when modifying data"""
        self._auto_timestamp_last_updated = False
        with ExitStack() as stack:
            _ = [
                stack.enter_context(statement.disable_last_updated())
                for statement in self.statements
            ]
            try:
                yield self
            finally:
                self._auto_timestamp_last_updated = True

    def to_json(self, **kwargs: Any) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(exclude_none=True, **kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Document":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
