# ADR 0010: Condition identity and phrasing

Status: accepted. Supersedes nothing; extends ADR 0005.

A condition is identified by its `id`. `kind` names what that condition checks
and is stable for a given `id` across runs, outcomes, and releases, so grouping
or routing by `kind` is safe. What the check found goes in `reason`, which
varies. `summary` is chosen from `outcome`, so a clear row reads as the pass and
an active row reads as the failure; it is never phrased as the condition
regardless of outcome.

Severity deliberately does vary for one `id`: an unreachable resolver is a
warning, a rejected credential is critical. Severity states how much the current
outcome matters, not what was checked, so it belongs with the outcome rather
than with the identity.

0.1.0 violated the first two rules. One filter condition reported
`required_filter_stale` and `required_filter_state_drift` under one `id` on
consecutive runs, and clear rows asserted the failure they had ruled out.
