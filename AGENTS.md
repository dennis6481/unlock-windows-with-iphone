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

## Project
- The minimum system requirement for Windows is Windows 10. For iOS, refer to the project settings. No compatible code for lower version is necessary.