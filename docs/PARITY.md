# Python v1 parity contract

The frozen Python oracle is authoritative for valid current inputs. Sentinel
intentionally differs only where the contract requires strict invalid-data
rejection, per-upstream retention, policy evaluation, transactional state, or
unambiguous run health.

| Area | Python v1 | Sentinel v1 |
| --- | --- | --- |
| Target order | Sequential targets; status then stats | Targets bounded concurrently; allowlisted calls remain sequential per target |
| Auth | 401/403 alerts immediately; per-target 15-minute pause | Exact parity |
| Other API failure | Four evaluated failures | Exact parity |
| Missing evaluation | Prior counter/latch freezes | Exact parity through `not_evaluated` |
| Protection | Only literal `true`; two-run alert | Same threshold; missing/wrong type is incomplete rather than false |
| Counters | Coercion, truncation, negative clamp, invalid-to-zero | Require nonnegative JSON integers and `blocked <= queries` |
| Processing latency | Invalid-to-zero; negative appears healthy | Require finite nonnegative number |
| Upstreams | Ignore malformed entries, default zero, retain maximum only | Strict array; retain identity/history and derive same maximum |
| Top client | Retain numeric maximum share only | Exact retained privacy boundary |
| Zero queries | Ratios become explicit zero | Exact parity |
| Latency boundary | Strictly greater than threshold | Exact parity |
| Aggregate gate | Every target must succeed | Every explicit behavior-group member must complete |
| Baseline | Seven days plus 36 same-wall-hour samples | Exact parity |
| DST | Host local repeated/skipped wall hours | Explicit IANA zone with equivalent repeated/skipped hours |
| Query anomaly | Frozen median/MAD formula | Exact parity |
| Blocked anomaly | Frozen minimum query and deviation formula | Exact parity |
| Samples | Inclusive prune before append; append on complete group only | Exact parity |
| Latching | Sustain once, one-run recovery, omitted keys freeze | Exact parity |
| Notifications | Alert batch with summary/detail, then resolution batch; priority 0/-1 | Same batching/order/priorities, but external payloads contain summaries only; detailed evidence stays local |
| State | Atomic JSON replace; limited aggregate history | Transactional versioned SQLite and bounded detailed history |
| Success marker | Updated even for all-target failure | Explicit per-run/target completeness; all-failed is unhealthy |
| Ordinary findings | Exit zero after successful delivery | Exit zero by default; `--fail-on` is operator-selected |
| Policy parity | Absent | Declared upstream/filter/rewrite read-only findings |
| Mutation | No current mutation call, but generic endpoint helper | Mutation cannot be represented by the typed client |

Key constants and formulas:

- Authentication cooldown: 900 seconds.
- API, processing, upstream, and behavioral sustain: four runs.
- Protection sustain: two runs. Authentication sustain: one run.
- Every recovery requires one evaluated clear run.
- Statistics window: 3,600,000 milliseconds.
- Processing threshold: strictly greater than 0.500 seconds.
- Upstream threshold: strictly greater than 0.750 seconds.
- Baseline: at least seven days old and 36 same-local-hour samples.
- Scaled MAD: `1.4826 * median(abs(value - median))`, floor `1e-9`.
- Query spike: `queries > max(3*median, median + 8*MAD, 500)`.
- Blocked-ratio anomaly: at least 100 queries and absolute deviation strictly
  greater than `max(0.20, 8*MAD)`.
- Retention keeps samples at the inclusive 21-day cutoff and appends only after
  every member of the behavior group completed.
- Unevaluated conditions never increment, clear, or resolve.
- Alert batches precede resolution batches. Only confirmed delivered alerts may
  later produce a resolution.

Invalid JSON types, missing required fields, negative/non-finite metrics,
fractional counters, blocked counts above query counts, malformed mapping
entries, duplicates, and unsupported versions are incomplete observations. The
Python oracle's silent zero defaults for those cases are not parity targets.
