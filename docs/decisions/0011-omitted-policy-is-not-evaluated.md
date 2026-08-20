# ADR 0011: Omitted policy is not evaluated

Status: accepted.

Policy is opt-in per target and per declared field. An omitted declaration
creates no condition in `evaluations[]`: no target policy creates no policy
conditions, and an omitted field creates no condition for that field. In
particular, an omitted upstream set is absent rather than `clear`, because
`clear` would assert that a declared expectation was checked and satisfied.

Declarations map independently to conditions: protection state, upstream mode,
upstream set, each required filter, the global rewrite setting, and each required
rewrite. Operational API and latency conditions do not depend on policy and
remain evaluated. Removing a declaration does not clear or advance its retained
latch; if the declaration returns later, its stable condition identifier resumes
the retained state.

Independence governs which conditions exist, not which observations a condition
may read. A required rewrite declared `enabled = true` reads the resolver's
global rewrite switch, because an entry cannot be reported as matching while the
switch that would make it resolve is off or unreadable; that reports as
`globally_disabled` on the rewrite's own condition and still creates no condition
for the undeclared switch. A declaration is only ever `clear` when the thing it
asked for actually holds.

This changes only whether an operator asked a policy question. It does not turn
missing or invalid AdGuard data into a healthy value, and it does not weaken the
strict request or response boundary from ADR 0003.
