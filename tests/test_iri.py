from contextlib import nullcontext

import pytest

from vexipy._iri import Iri, check_iri

TEST_IRIS = [
    ("foo", pytest.raises(ValueError, match='Invalid IRI: "foo"')),
    (
        "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        None,
    ),
    (
        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
        None,
    ),
]


@pytest.mark.parametrize("iri, exception", TEST_IRIS)
def test_iri_validator_properly_validates_iris(iri, exception):
    with exception or nullcontext():
        assert check_iri(iri) == iri


def test_iri_attribute():
    assert Iri("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7")
