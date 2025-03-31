from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from py_vex.statement import Statement
from py_vex._iri import Iri


class Document(BaseModel):
    """
    A data structure that groups together one or more VEX statements.
    """

    context: str = Field(alias="@context")
    id: Iri = Field(alias="@id")
    author: str
    role: Optional[str] = None
    timestamp: str
    last_updated: Optional[str] = None
    version: int
    tooling: Optional[str] = None
    statements: List[Statement] = []

    model_config = ConfigDict(populate_by_name=True)

    def to_json(self, **kwargs) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Document":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
