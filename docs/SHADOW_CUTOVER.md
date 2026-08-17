# Shadow validation and cutover

This repository does not deploy itself.

The later dotfiles task must keep the Python monitor and Healthchecks ownership
unchanged while adding a notification-disabled Sentinel shadow unit with a
separate state directory. Sentinel runs every five minutes for eight continuous
days. Acceptance requires at least 2,189 of 2,304 runs paired within 90 seconds,
no unexplained condition/transition mismatch, documented metric tolerances, and
no non-GET AdGuard traffic.

Only after Adam accepts that report may dotfiles pin the package, retarget the
Healthchecks unit, explicitly import a final Python snapshot, and let the operator
build and switch the monitor host. The previous NixOS generation, Python unit, and untouched
JSON state remain the rollback authority. Static checks and package builds are
never described as live timer, credential, notification, or deployment proof.
