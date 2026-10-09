#!/usr/bin/env python3
"""Self-tests of the black-box helper modules (not a suite).

``python3 tests/e2e/_selftest.py`` runs them directly. Every suite also
calls :func:`self_test` first, so they run under the CI suite contract
(CI runs only the files whose names do not start with ``_``) and a
harness regression, such as a YAML reader that became lenient, fails CI
even when every protocol check still passes.
"""
from __future__ import annotations

import io
import sys
import unittest

import _bench
import _fixtures
import _harness
import _node
import _yaml

MODULES = (_harness, _fixtures, _yaml, _node, _bench)


def load_suite() -> unittest.TestSuite:
    loader = unittest.TestLoader()
    return unittest.TestSuite(loader.loadTestsFromModule(module) for module in MODULES)


def self_test(results: _harness.Results) -> bool:
    """Run every helper module's tests; one ``harness/self-test`` record."""
    stream = io.StringIO()
    outcome = unittest.TextTestRunner(stream=stream, verbosity=1).run(load_suite())
    problems = outcome.failures + outcome.errors + [
        (test, f"skipped: {reason}") for test, reason in outcome.skipped]
    if outcome.testsRun == 0 or problems:
        details = "\n".join(f"{test.id()}:\n{text[-1500:]}" for test, text in problems)
        return results.record("harness/self-test", False,
                              f"{len(problems)} of {outcome.testsRun} self-tests failed\n{details}")
    return results.record("harness/self-test", True, f"{outcome.testsRun} tests")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(load_suite())
    sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)
