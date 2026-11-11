"""The ``dynamodb`` store backend: an AWS DynamoDB table."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._factory import StoreFactory, env_flag

if TYPE_CHECKING:
    from key_value.aio.stores.base import BaseContextManagerStore

    from ._settings import OAuthStateSettings


class DynamoDBStoreFactory(StoreFactory):
    extra = "dynamodb"
    location_variables = ("STORE_DYNAMODB_TABLE",)

    def settings_from_env(self, environ: Mapping[str, str]) -> dict[str, Any]:
        return {
            "store_dynamodb_table": environ.get("STORE_DYNAMODB_TABLE") or None,
            "store_dynamodb_region": environ.get("STORE_DYNAMODB_REGION") or None,
            "store_dynamodb_auto_create": env_flag(
                environ, "STORE_DYNAMODB_AUTO_CREATE", default=False
            ),
        }

    def validate(self, settings: OAuthStateSettings) -> None:
        if not settings.store_dynamodb_table:
            raise ValueError("STORE_BACKEND=dynamodb requires STORE_DYNAMODB_TABLE")

    def location(self, settings: OAuthStateSettings) -> str:
        return f"DynamoDB table {settings.store_dynamodb_table!r}"

    def create(self, settings: OAuthStateSettings) -> BaseContextManagerStore:
        from key_value.aio.stores.dynamodb import DynamoDBStore

        assert settings.store_dynamodb_table is not None  # validate()
        return DynamoDBStore(
            table_name=settings.store_dynamodb_table,
            region_name=settings.store_dynamodb_region,
            auto_create=settings.store_dynamodb_auto_create,
        )
