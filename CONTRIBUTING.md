<!-- Created by Rui MA on 21 Oct 2026 -->

# Contributing

Open pull requests against `main`. Discuss substantial changes in an issue before starting work.

Keep each pull request focused on one objective. Include a description of the change, validation results and any checks not performed.

## Code and architecture

- Reuse suitable existing implementations. Keep each shared contract and decision rule in one authoritative source; cross-language consumers must read it or use generated definitions.
- Make the smallest change that solves the problem. Avoid unrelated changes and abstractions, defensive logic or recovery mechanisms without a demonstrated need.
- Fix identifiable root causes. Before introducing a workaround, explain the cause and why it cannot be prevented at its source. Do not compensate for preventable installation errors with cleanup code.
- Report errors explicitly. Use fallback behavior only when required by the intended behavior or strictly necessary, and explain why.
- Keep diagnostic and probe code separate from product code unless inclusion has maintainer approval and supporting evidence.

## Compatibility

- Follow the minimum Windows requirements in the [Windows developer guide](windows/README.md#compatibility).
- Do not support OS versions below the project minimums. Remove obsolete compatibility code when it is related to your change.
- Before replacing installation paths or changing persisted formats, agree with the maintainer on compatibility with older product versions.
- When older-version compatibility is unnecessary, remove superseded implementations, migration branches, contracts, tests and documentation in the same change.

## File authorship

- Start new files with `Created by <name> on <dd mmm yyyy>`, using the file's comment syntax.
- Check the original creator before editing. If you are a different person, add `Modified by <name> on <dd mmm yyyy>` below the author comment; otherwise, leave it unchanged.
- Use real names from Git configuration or history, never AI agent names. Avoid duplicate or contradictory author comments.

## Documentation and validation

- Update documentation affected by your change, including `README.md` where relevant. Keep edits concise and follow the existing style.
- Follow the [Windows developer guide](windows/README.md) for builds and tests.
