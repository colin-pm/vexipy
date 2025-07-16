"""
Defines the Statement model for the impact a vulnerability has on one or more software "products".
"""

import warnings
from datetime import datetime
from typing import Any, Iterable, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from vexipy._iri import Iri
from vexipy._util import utc_now
from vexipy.component import Product
from vexipy.status import StatusJustification, StatusLabel
from vexipy.vulnerability import Vulnerability


class Statement(BaseModel):
    """
    A statement is an assertion made by the document's author about the impact a
    vulnerability has on one or more software products. The statement has three
    key components that are valid at a point in time: status, a vulnerability,
    and the product to which these apply.

    :param id: Optional IRI identifying the statement to make it externally referenceable.
    :param version: Optional integer representing the statement's version number. Defaults to zero, required when incremented.
    :param vulnerability: A struct identifying the vulnerability.
    :param timestamp: Timestamp is the time at which the information expressed in the Statement was known to be true. Cascades down from the document, see Inheritance.
    :param last_updated: Timestamp when the statement was last updated.
    :param products: List of product structs that the statement applies to.
    :param status: A VEX statement MUST provide the status of the vulnerabilities with respect to the products and components listed in the statement. status MUST be one of the labels defined by VEX (see Status), some of which have further options and requirements.
    :param supplier: Supplier of the product or subcomponent.
    :param status_notes: A statement MAY convey information about how status was determined and MAY reference other VEX information.
    :param justification: For statements conveying a not_affected status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. Justifications are fixed labels defined by VEX.
    :param impact_statement: For statements conveying a not_affected status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. An impact statement is a free form text containing a description of why the vulnerability cannot be exploited. This field is not intended to be machine readable so its use is highly discouraged for automated systems.
    :param action_statement: For a statement with "affected" status, a VEX statement MUST include a statement that SHOULD describe actions to remediate or mitigate the vulnerability.
    :param action_statement_timestamp: The timestamp when the action statement was issued.
    """

    id: Optional[Iri] = Field(alias="@id", default=None)
    version: Optional[int] = None
    vulnerability: Vulnerability
    timestamp: Optional[datetime] = Field(default_factory=utc_now)
    last_updated: Optional[datetime] = None
    products: Optional[Tuple[Product, ...]] = None
    status: StatusLabel
    supplier: Optional[str] = None
    status_notes: Optional[str] = None
    justification: Optional[StatusJustification] = None
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    action_statement_timestamp: Optional[datetime] = None

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    @field_validator("products", mode="before")
    @classmethod
    def convert_to_tuple(
        cls, v: Optional[Iterable[Product]]
    ) -> Optional[Tuple[Product, ...]]:
        """
        Converts an iterable of Components to a tuple of Components.

        :param v: Iterable of Components or None.
        :return: Tuple of objects or None if not provided.
        """
        return None if v is None else tuple(v)

    @model_validator(mode="after")
    def check_review_fields(self) -> "Statement":
        """
        Validates that a not-affected status includes a justification or impact statement.
        Warns if only an impact statement is provided without justification.

        :raises ValueError: If status is "NOT_AFFECTED" and both justification and impact statement are not provided.
        :return: The validated Statement instance.
        """
        if self.status == StatusLabel.NOT_AFFECTED:
            # Note: truthiness should just be checked here, but upstream schema allows empty strings
            if self.justification is None and self.impact_statement is None:
                raise ValueError(
                    "A not-affected status must include a justification or impact"
                    " statement"
                )
            if self.impact_statement is not None and self.justification is None:
                warnings.warn(
                    "The use of an impact statement in textual form without a"
                    " justification field is highly discouraged as it breaks VEX"
                    " automation and interoperability."
                )
        return self

    @model_validator(mode="after")
    def check_action_statement(self) -> "Statement":
        """
        Validates that an affected status includes an action statement.

        :raises ValueError: If action statement is missing for a vulnerability with an affected status.
        :return: The validated Statement instance.
        """
        if self.status == StatusLabel.AFFECTED and self.action_statement is None:
            raise ValueError(
                'For a statement with "affected" status, a VEX statement MUST include'
                " an action statement that SHOULD describe actions to remediate or"
                " mitigate the vulnerability."
            )
        return self

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        """
        Serializes the timestamp to ISO 8601 string format.

        :param value: The datetime value to serialize.
        :return: ISO 8601 formatted string.
        """
        return value.isoformat()

    def update(self, **kwargs: Any) -> "Statement":
        """
        Returns a new Statement instance with updated fields and timestamp.

        If a timestamp is not provided in kwargs, the new document instance will default to the current UTC time.

        :param kwargs: Fields to update in the model.
        :return: Updated Statement instance.
        """
        obj = self.model_dump()
        obj.update(
            (kwargs | {"timestamp": utc_now()}) if "timestamp" not in kwargs else kwargs
        )
        return Statement(**obj)

    def to_json(self, **kwargs: Any) -> str:
        """
        Serializes the Statement model to a JSON string.

        :param kwargs: Additional keyword arguments for serialization.
        :return: JSON string representation of the model.
        """
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, json_string: str) -> "Statement":
        """
        Creates a Statement instance from a JSON string.

        :param json_string: JSON string to deserialize.
        :return: Statement instance.
        """
        return cls.model_validate_json(json_string)
