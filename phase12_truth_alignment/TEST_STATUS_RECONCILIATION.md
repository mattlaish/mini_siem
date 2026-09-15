# Test Status Reconciliation

Testing deferred and failing tests are separate states.

Deferred:
Implementation exists but validation has not run.

Failing:
Implementation gap or regression exists.

Tests must not be described as deferred when they fail due to missing implementation.
