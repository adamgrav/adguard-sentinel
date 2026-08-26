# ADR 0012: Behavioural conditions measure rates over windows

Status: accepted. Extends ADR 0007 and ADR 0010.

AdGuard Home reports statistics as a counter that resets on its own local hour.
A single reading is therefore a partial hour total, and its size depends on when
in the hour it was taken far more than on how much traffic the resolver saw. On
a live deployment the same traffic read as 169 queries just after the reset and
10,167 just before it, a 60-fold spread produced entirely by sampling phase.

Comparing such readings against each other cannot work. A ramp sampled uniformly
has a maximum near twice its median, so a threshold set at three times the
median is unreachable by construction, and dispersion measured across the ramp
inflates the deviation term that is supposed to bound it. Both behavioural
conditions were therefore incapable of firing, and the absolute deviation floor
compounded it: a floor wider than the entire observed range of a ratio makes a
collapse to zero indistinguishable from health.

Behavioural conditions consequently compare a **window**: the difference between
two consecutive samples, divided by the elapsed time. A window means the same
thing wherever in the hour it falls, and it responds to a change within one run
interval rather than diluting it across the hour so far.

A pair of samples yields no window when the counter decreased, or when more than
one run interval separates them. Both are skipped rather than estimated.
Estimating the first would require assuming where the resolver's hour boundary
falls, which is a timezone the monitor does not observe and should not guess;
estimating the second would average a rate across an outage. A run without a
window leaves the behavioural conditions not evaluated, which under ADR 0005
neither increments, clears, nor resolves them.

Blocking collapse is a **separate condition** from blocked-ratio deviation, and
critical rather than warning. "Blocking has stopped" is a different question from
"the ratio moved", it is the failure an operator most needs to hear about, and a
symmetric deviation test buries it in the tail of a distribution. It is also the
only condition that reports blocking having failed while protection is enabled
and every declared filter is present, enabled, and fresh — the case where policy
checking is satisfied and blocking is not happening.

`aggregate:query-spike` is retired rather than repurposed. Its `kind`,
`combined_query_volume`, named a count, and ADR 0010 requires `kind` to be stable
for a given `id` across releases; a rate is a different quantity, not a better
measurement of the same one. It is replaced by `aggregate:query-rate` with kind
`combined_query_rate`. `aggregate:blocked-ratio` keeps its identifier, because
`combined_blocked_ratio` still names exactly what it checks and only the
measurement window changed. Neither retired condition had ever been active, so
no latch was carried.

The persisted sample stays the raw cumulative counter. Windows are derived on
read, so the state schema, its checksum, and the `aggregate_observations`
columns are unchanged, existing databases open without migration, and the
accumulated baseline is not discarded by this change.
