"""Smoke test: the package imports and carries a version."""


def test_version_is_exposed() -> None:
    import glassbox

    assert glassbox.__version__
