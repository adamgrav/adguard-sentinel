# Behavior contract

The following rules are the product's behavior contract. Changing any of them is
a behavior change that must be reflected here and in the run-report schema:

- Authentication rejection alerts after one observation and pauses that target
  for 900 seconds.
- API availability, processing latency, upstream latency, policy drift, and
  behavioral anomalies use their configured sustain counts. Protection uses
  its own configured count. Recovery is independently configurable.
- Processing latency is active only when strictly greater than its threshold.
  Upstream latency is the maximum validated per-upstream average and also uses
  a strict greater-than comparison.
- Conditions that cannot be evaluated do not increment, clear, or resolve.
- Only declared policy fields create policy conditions. An omitted target policy
  or policy field is absent from `evaluations[]`; it is not clear or
  not-evaluated.
- Omitting `[behavioral_baseline]` produces no aggregate observation or
  behavioural conditions.
- A condition that stops being produced retains its latch. Withdrawing a policy
  declaration or `[behavioral_baseline]` neither resolves a firing condition nor
  advances a recovering one, and restoring the declaration resumes the retained
  state under the same condition identifier.
- Behavioral aggregation advances only after every declared group member has a
  complete observation.
- The baseline requires the configured age and same-local-hour sample count.
  It uses median, scaled MAD `1.4826`, and a deviation floor of `1e-9`.
- Query volume is active above
  `max(3 * median, median + 8 * scaled_mad, 500)`.
- Blocked ratio requires at least 100 queries and an absolute deviation above
  `max(0.20, 8 * scaled_mad)`.
- Retention keeps samples at the inclusive cutoff and appends only complete
  aggregate observations.
- Alerts are batched before resolutions. External messages contain summaries
  only; structured evidence remains local.
- An ambiguous notification attempt is quarantined and never automatically
  resent. A resolution is eligible only after confirmed alert delivery.

Missing fields, wrong JSON types, fractional or negative counters, non-finite
or negative metrics, duplicate normalized values, blocked counts above query
counts, and unsupported server versions make the affected target incomplete.
