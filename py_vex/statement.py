import warnings
from typing import Any, Iterable, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from py_vex._iri import Iri
from py_vex.component import Component
from py_vex.status import StatusJustification, StatusLabel
from py_vex.vulnerability import Vulnerability


class Statement(BaseModel):
    """
    A statement is an assertion made by the document's author about the impact a
    vulnerability hason one or more software "products". The statement has three
    key components that are valid at a point in time: status, a vulnerability,
    and the product to which these apply.
    """

    id: Optional[Iri] = Field(alias="@id", default=None)
    version: Optional[int] = None
    vulnerability: Vulnerability
    timestamp: Optional[str] = None
    products: Optional[Tuple[Component, ...]] = None
    status: StatusLabel
    supplier: Optional[str] = None
    status_notes: Optional[str] = None
    justification: Optional[StatusJustification] = None
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    action_statement_timestamp: Optional[str] = None

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    @field_validator("products", mode="before")
    @classmethod
    def convert_to_tuple(
        cls, v: Optional[Iterable[Component]]
    ) -> Optional[Tuple[Component, ...]]:
        """Convert dict input to tuple of tuples"""
        return None if v is None else tuple(v)

    @model_validator(mode="after")
    def check_review_fields(self) -> "Statement":
        if self.status == StatusLabel.NOT_AFFECTED:
            # Note: truthiness should just be checked here, but upstream schema allows empty strings
            if self.justification is None and self.impact_statement is None:
                raise ValueError(
                    "A not-affected status must include a justification or impact statement"
                )
            if self.impact_statement is not None and self.justification is None:
                warnings.warn(
                    "The use of an impact statement in textual form without a justification field is highly discouraged as it breaks VEX automation and interoperability."
                )
        return self

    @model_validator(mode="after")
    def check_action_statement(self) -> "Statement":
        if self.status == StatusLabel.AFFECTED and self.action_statement is None:
            raise ValueError(
                'For a statement with "affected" status, a VEX statement MUST include an action statement that SHOULD describe actions to remediate or mitigate the vulnerability.'
            )
        return self

    def to_json(self, **kwargs: Any) -> str:
        """Return a JSON string representation of the model."""
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Statement":
        """Create a model instance from a JSON string."""
        return cls.model_validate_json(json_string)
