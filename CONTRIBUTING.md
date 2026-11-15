# Contributing

Issues and pull requests are welcome. Open an issue first for anything large, so we can agree the approach before you write it.

## Set up

You need [uv](https://docs.astral.sh/uv/), [just](https://github.com/casey/just) and [podman](https://podman.io/). Then:

```bash
just deps      # pinned Python tools and the test collections
just lint      # yamllint, ansible-lint (production profile), ruff, zizmor
just unit      # every check on real and broken probe data
just test default rhel9
```

`just` on its own lists every recipe.

## Rules

- Every variable is in `defaults/main.yml`, `meta/argument_specs.yml` and the README variables table, with the same default and description in all three.
- Internal variables start with `__mde_linux_checks_` and live in `vars/main.yml` or are registered in tasks.
- **Check ids are a contract.** Waivers, limits and comparisons in reports select checks by id, so never reuse one for a different check or rename one without a changelog entry. Every check is in the README's tables with its severity and the reason it exists.
- **Read on the host, judge on the control node.** The probe module only reads, and keeps to Python 3.6; the judgement in `filter_plugins/mde_linux_checks.py` gets a unit test for every way a check can fail.
- **Only documented mdatp fields**, read from `mdatp health`'s text output. A field a version lacks must make its check skip, not fail.
- **Nothing fails the play.** Record a failed or timed-out test and carry on; the report decides.
- **Fixtures come from real hosts**, with device ids replaced by made-up ones.
- Docs and comments are in British English.

## Commits and releases

Write commit subjects in the imperative, wrapped at 72 characters. Add an entry under Unreleased in `CHANGELOG.md`.

Maintainers release with `just release 1.2.3`, which tags and pushes. The Release workflow then creates the GitHub release and imports the tag into Galaxy.
