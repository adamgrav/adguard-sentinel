# ADR 0005: Findings, latches, and exits

Status: accepted.

A finding describes the current observation. Sustain and recovery counters
control notification transitions independently. `--fail-on` evaluates current
finding severity, not notification state. The deployed default is `never`.
Dedicated exit codes distinguish config, zero complete targets, notification
delivery, and persistence failures.
