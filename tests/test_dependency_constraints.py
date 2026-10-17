"""Tests for the dependency constraints this package publishes.

``uv.lock`` is a development artifact: it is excluded from wheels, so what
consumers actually resolve against is the ``dependencies`` metadata built from
``pyproject.toml``. A locked CI run therefore proves nothing about a fresh
install, and the checks below assert the published metadata rather than the
installed versions.
"""

from importlib.metadata import requires

from packaging.requirements import Requirement


def _constraint(distribution: str) -> Requirement:
    """Return the published requirement on ``distribution``."""
    for entry in requires("fastmcp-seaworthy") or []:
        requirement = Requirement(entry)
        if requirement.name == distribution and requirement.marker is None:
            return requirement
    raise AssertionError(f"{distribution} is not a declared dependency")


class TestPublishedDependencyConstraints:
    """Versions this code cannot run on must be unresolvable for consumers."""

    def test_fastmcp_before_4_0_8_is_excluded(self):
        """4.0.8 is the first release with all the OAuthProxy security fixes.

        4.0.4 rejects ID-JAG tokens unless identity assertion is configured,
        4.0.6 keeps Google access tokens out of request URLs, and 4.0.8 revokes
        the upstream refresh token instead of sending the proxy's own token
        upstream.
        """
        specifier = _constraint("fastmcp").specifier
        assert not specifier.contains("4.0.7")
        assert not specifier.contains("3.4.7")
        assert specifier.contains("4.0.8")

    def test_fastmcp_5_is_excluded(self):
        """serve_http() depends on fastmcp's private ``_lifespan_manager``.

        One FastMCP server backs an ASGI app per public hostname, and the
        server's lifespan is shared between them only because
        ``_lifespan_manager`` is reference-counted. A private method carries no
        compatibility promise, so a major that renames it or drops the counting
        must be unresolvable rather than break every consumer at startup -- or,
        worse, run the server lifespan once per hostname.
        """
        specifier = _constraint("fastmcp").specifier
        assert not specifier.contains("5.0.0")
        assert specifier.contains("4.1.0")
