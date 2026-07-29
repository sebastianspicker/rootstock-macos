---
name: Feature Request
about: Suggest a bounded change to a Rootstock component
title: "[feature] "
labels: enhancement
---

## Problem

What problem does this solve?

## Component Scope

- Affected component: Core collector / Core graph or viewer / cve-scan /
  Rootstock Red / Rootstock Blue / RootstockMacFacts
- Does this change an existing artifact contract or optional family bridge?
- Does it require an explicit boundary between components rather than a shared
  runtime dependency?

## Proposed Solution

Describe the feature or change.

## Use Case

- Who benefits? Operator / assessor / incident responder / researcher
- Example scenario:

## Safety Scope

- Does this keep the collector passive and local-only?
- Does it require network access, active probing, or new privileges?
- Could it expose sensitive scan artifacts?
- Does it preserve the alpha boundary that components may change independently?

Do not propose a license assignment for `packages/RootstockMacFacts/`; its
license scope is unresolved.

## Verification

What tests, fixture updates, or smoke checks should prove this works?

## Alternatives Considered

## Additional Context
