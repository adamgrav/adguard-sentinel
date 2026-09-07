# ADR 0006: Pushover ambiguity

Status: accepted.

Confirmed success requires HTTP 200, JSON `status=1`, and a nonempty request ID.
Definitely undelivered
retryable attempts remain pending. Permanent rejections fail. A timeout or
connection loss after transmission is quarantined as unknown and never resent
automatically. A resolution is eligible only after confirmed alert delivery.
Pushover payloads contain condition summaries only; structured evidence and raw
error detail remain local to the report and state database.
