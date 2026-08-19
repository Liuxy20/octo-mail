# Implementation Plan

1. Change WebAPI integration tests first and confirm the new Agent-draft cases
   fail against the current implementation.
2. Make the smallest route/handler authorization changes while preserving all
   existing version, claim, and account-isolation paths.
3. Add the three octo-cli registry operations and update command/Skill tests and
   documentation.
4. Run targeted tests, then each repository's full formatting, vet, test, build,
   race, and lint gates.
5. Review both diffs against the PRD and confirm no unrelated repository changed.
