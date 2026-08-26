# Contributing to TraceVeil

Thank you for considering a contribution. TraceVeil’s value depends on predictable behavior and credible limits, so a smaller well-tested change is preferable to a broad feature with ambiguous privacy semantics.

## Before opening a pull request

Start with an issue describing the concrete telemetry shape, policy need, expected artifact behavior, and non-goal. Do not include real secrets, personal data, proprietary prompts, or production telemetry in issues, fixtures, screenshots, or pull requests.

Install development dependencies and run the local gate:

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## Contribution principles

Changes must preserve deterministic output for equal input and policy; must not serialize raw matched content into evidence or reports; must document new policy behavior and limitations; and must include a test demonstrating both intended handling and non-disclosure.

If a contribution changes the evidence schema or policy semantics, add a migration note and a fixture proving compatibility behavior. New detectors should describe their false-positive and false-negative boundaries explicitly.

## Pull-request checklist

- [ ] I added or updated tests.
- [ ] I ran `pytest` and `ruff check .`.
- [ ] My fixtures contain only synthetic or public-safe values.
- [ ] My change does not log or serialize raw matched data.
- [ ] I updated docs and the changelog when behavior changed.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

