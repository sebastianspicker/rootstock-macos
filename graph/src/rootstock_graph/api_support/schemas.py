"""Request bodies accepted by the Rootstock Graph API routes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from ..constants import NODE_KEY_PROPERTY


class MarkOwnedRequest(BaseModel):
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None
    label: str | None = None
    keys: list[str] | None = None

    @field_validator("label")
    @classmethod
    def label_is_allowed(cls, label: str | None) -> str | None:
        if label is not None and label not in NODE_KEY_PROPERTY:
            raise ValueError(f"Unknown label. Valid labels: {', '.join(sorted(NODE_KEY_PROPERTY))}")
        return label

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


MAX_QUERY_PARAMS = 32


class QueryRunRequest(BaseModel):
    params: dict[str, Any] | None = None

    @field_validator("params")
    @classmethod
    def params_are_small_scalars(cls, params: dict[str, Any] | None) -> dict[str, Any] | None:
        if params is None:
            return params
        if len(params) > MAX_QUERY_PARAMS:
            raise ValueError(f"At most {MAX_QUERY_PARAMS} query parameters are allowed")
        for key, value in params.items():
            if value is not None and not isinstance(value, (str, int, float, bool)):
                raise ValueError(f"Parameter {key!r} must be a string, number, boolean or null")
        return params


class CypherRequest(BaseModel):
    cypher: str
    params: dict[str, Any] | None = None
