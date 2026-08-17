# ADR 0003: Strict external data

Status: accepted.

Required fields use strict JSON types and domain checks. Missing, fractional,
negative, non-finite, duplicate, or structurally unsupported data makes the
target incomplete. Empty arrays and zero queries remain valid only where the API
semantics explicitly allow them. Unknown response fields may be ignored for
forward-compatible patch releases.
