"""recommendation_rule.py - The rule record shared by the recommendation rule tables."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecommendationRule:
    key: str
    category: str
    title: str
    text: str
    priority: str
    technique_ids: tuple[str, ...]
    condition: str
    target: str = "app"  # "app" (bound `app`) or "host" (bound `c`)
