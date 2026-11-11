"""The interface every external store backend implements."""

from __future__ import annotations

import warnings
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from key_value.aio.stores.base import BaseContextManagerStore

    from ._settings import OAuthStateSettings

_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off")


def env_flag(environ: Mapping[str, str], name: str, *, default: bool) -> bool:
    """Read a boolean environment variable, or ``default`` when it is unset.

    An unrecognized value is an error rather than a silent default: a typo, or
    a plausible-looking ``STORE_DYNAMODB_AUTO_CREATE=enabled``, should not
    quietly resolve to whichever state the operator was trying to leave.
    """
    raw = environ.get(name)
    if raw is None or raw == "":
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    raise ValueError(
        f"{name} must be one of {', '.join((*_TRUTHY, *_FALSY))} -- got {raw!r}"
    )


class StoreFactory(ABC):
    """Maps :class:`OAuthStateSettings` to one of py-key-value-aio's stores.

    The stores themselves are py-key-value-aio's; a backend here owns only what
    is specific to it: reading its settings from the environment, refusing
    settings it could not use, naming where it keeps the state, and
    constructing the store. Everything shared -- the signing key requirement,
    encryption, the lifecycle -- stays with the caller.

    A subclass must import its store class and the store's dependencies inside
    :meth:`create` only: the backends are optional extras, and a deployment on
    the default file store must neither need nor load them.
    """

    extra: ClassVar[str]
    """The ``fastmcp-seaworthy`` extra that installs the backend's dependencies."""

    location_variables: ClassVar[tuple[str, ...]]
    """The settings that decide where the state lives, named in startup errors."""

    @abstractmethod
    def settings_from_env(self, environ: Mapping[str, str]) -> dict[str, Any]:
        """Read the backend's own settings, as ``OAuthStateSettings`` keywords.

        Empty values count as unset.
        """

    @abstractmethod
    def validate(self, settings: OAuthStateSettings) -> None:
        """Refuse settings the backend could not start with.

        Called on construction of ``settings`` when the backend is selected,
        so a bad value fails together with every other setting rather than at
        the first request.

        Raises:
            ValueError: Naming the setting at fault.
        """

    @abstractmethod
    def location(self, settings: OAuthStateSettings) -> str:
        """Name where the state lives, for the startup log -- no secrets."""

    @abstractmethod
    def create(self, settings: OAuthStateSettings) -> BaseContextManagerStore:
        """Construct the store, importing its class here and nowhere else."""

    def build(
        self, settings: OAuthStateSettings
    ) -> tuple[BaseContextManagerStore, str]:
        """Construct the store and the description :class:`ClientStorage` keeps.

        Raises:
            RuntimeError: If the backend's extra is not installed.
        """
        try:
            with warnings.catch_warnings():
                # py-key-value-aio warns on every construction that the store's
                # Python API may still change. That is addressed to whoever
                # calls the constructor -- this package, whose range fastmcp's
                # own <0.5 pin bounds -- not to the operator reading the
                # startup log.
                warnings.filterwarnings(
                    "ignore",
                    message="A configured store is unstable",
                    category=UserWarning,
                )
                store = self.create(settings)
        except ImportError as e:
            raise RuntimeError(
                f"STORE_BACKEND={settings.store_backend} needs the {self.extra!r} "
                f"extra: install fastmcp-seaworthy[{self.extra}]"
            ) from e
        variables = ", ".join(self.location_variables)
        return store, f"{self.location(settings)} ({variables})"
