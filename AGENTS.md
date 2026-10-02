## General rules

- Do not hide or silently ignore errors. Use fallback behavior only when explicitly requested or strictly necessary.
- After every technical implementation, check whether `README.md` needs to be updated.
- Do not run a build unless the user explicitly asks for one.
- If the `main` branch does not contain a product, do not add extra compatibility logic for an older version.

## Author comments in files

- Every new file must begin with an author comment using the appropriate comment syntax for that file:
  `Created by <real Git author name> on <date(dd mmm yyyy)>`.
- When modifying an existing file, first check the original creator's name.
- If the modifier and creator are the same real person, do not add a `Modified by` comment.
- If the modifier is a different real person, add this below the original author comment:
  `Modified by <real Git author name> on <date(dd mmm yyyy)>`.
- The author name must be a real person's name from Git history or Git configuration. Never use `Codex`, `Agent`, or any other agent name.
- Do not add duplicate or contradictory author comments.
- Do not add comments in the middle of a file

## Project

### System requirements
- The minimum supported Windows version is Windows 10.
- For iOS minimum-version requirements, refer to the project settings.
- Do not add compatibility code for versions below the minimum requirements.
- If such obsolete compatibility code is found while working on a task, remove it when it is related to that task.
- Do not remove unrelated compatibility code elsewhere.

## Implementation Rules

- MUST fix the root cause when it is identifiable.
- MUST NOT add cleanup workarounds to compensate for an incorrect
  installation state when that state can be prevented at installation time.
- MUST NOT modify unrelated components.
- Keep each task focused on one explicit objective and make the smallest change
  that satisfies it.
- Validate the highest-risk assumption with the smallest isolated experiment
  before building product infrastructure around it.
- Diagnostic and probe code MUST remain separate from product code unless its
  use in the product has been explicitly approved and supported by evidence.
- MUST NOT add abstractions, defensive logic, recovery mechanisms, or backward
  compatibility without a validated requirement or a reproduced failure.
- Before adding a workaround, determine and document why the invalid state
  exists and whether it can be prevented at its source.
- Once a new path is established and `main` no longer needs the old path, remove
  the superseded implementation. Do not use glue code to maintain historical
  paths.
- In documentation and status reports, clearly distinguish observed results,
  inferences, and unverified assumptions. A successful partial experiment MUST
  NOT be presented as completion of a product feature.
- If a reference link is provided and used in an approved implementation, add it at the end of README.md.
- If a reference link is provided but is not used, do not add it in README.md

## Build and validation

- MUST NOT run builds, compilation, tests that trigger compilation, packaging, or installation unless the user explicitly requests it in the current task.
- Editing code does not imply permission to build it.
- Do not run a build merely to verify an implementation.
- Static inspection and non-build validation are allowed.
