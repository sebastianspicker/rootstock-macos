"""Request bodies accepted by the Rootstock Graph API routes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, model_validator


class MarkOwnedRequest(BaseModel):
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None
    label: str | None = None
    keys: list[str] | None = None

    @model_validator(mode="after")
    def has_one_selector(self) -> "MarkOwnedRequest":
        generic_selector = self.label is not None or self.keys is not None
        selectors = sum(
            (
                bool(self.bundle_ids),
                bool(self.usernames),
                generic_selector,
            )
        )
        if selectors != 1:
            raise ValueError("Specify exactly one owned-node selector")
        if generic_selector and ((self.label is None) != (self.keys is None) or not self.keys):
            raise ValueError("label and keys must be supplied together")
        return self


class ClearOwnedRequest(BaseModel):
    all: bool = False
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None


class QueryRunRequest(BaseModel):
    params: dict[str, Any] | None = None


class CypherRequest(BaseModel):
    cypher: str
    params: dict[str, Any] | None = None
