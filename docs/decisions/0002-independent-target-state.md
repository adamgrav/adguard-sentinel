# ADR 0002: Independent target state

Status: accepted.

Observations, auth cooldowns, conditions, and history are keyed by stable target
ID. They are never copied between targets. Only the explicitly configured
behavior group combines query and blocked totals; every group member must have a
complete run before it advances.
