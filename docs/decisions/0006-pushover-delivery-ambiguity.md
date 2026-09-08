# ADR 0006: Pushover ambiguity

Status: accepted.

Confirmed success requires HTTP 200, JSON `status=1`, and a nonempty request ID.
Definitely undelivered retryable attempts remain queued. Permanent rejections
fail. A timeout or connection loss after possible transmission becomes unknown
and is never resent automatically.

V2 commits an in-flight claim before sending and commits the result with the
episode's delivery state. A process death between those commits is ambiguous,
even if transmission might not have started. Quarantine takes precedence over
automatic replay. A resolution requires confirmed visible alert delivery for
the same episode; original membership and attempt evidence remain attributable.
[BEHAVIOR](../BEHAVIOR.md#notifications) owns batching and recovery rules.

Pushover payloads contain condition summaries only; structured evidence and raw
error detail remain local to the report and state database.
