"""Miscellaneous helper functions."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """
    Returns the current UTC datetime.

    :return: Current datetime in UTC timezone.
    """
    return datetime.now(timezone.utc)
