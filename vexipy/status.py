"""
Defines enums for vulnerability status labels and justifications.
"""

from enum import Enum


class StatusLabel(Enum):
    """
    Enum representing the status of a vulnerability for a component.

    Members:
        NOT_AFFECTED: The component is not affected by the vulnerability.
        AFFECTED: The component is affected by the vulnerability.
        FIXED: The vulnerability has been fixed in the component.
        UNDER_INVESTIGATION: The vulnerability is under investigation.
    """

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class StatusJustification(Enum):
    """
    Enum representing justifications for a vulnerability status.

    Members:
        COMPONENT_NOT_PRESENT: The component is not present in the product.
        VULNERABLE_CODE_NOT_PRESENT: The vulnerable code is not present in the component.
        VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: The vulnerable code is not in the execution path.
        VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: The vulnerable code cannot be controlled by an adversary.
        INLINE_MITIGATIONS_ALREADY_EXIST: Inline mitigations already exist for the vulnerability.
    """

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"
