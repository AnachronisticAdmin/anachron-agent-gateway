# Permission and identity flow

The embedding host authenticates a caller before passing an explicit principal to this core. Permission decisions are structured application input, not authority inferred from arbitrary prompt text.

## Fixture flow

- **Start:** The authenticated in-process caller starts a task with the owned fake subprocess.
- **Pause:** The fake agent offers an operation and options; no fixture file exists before a decision.
- **Correlate:** The bridge binds an offered choice to its caller/task, session, permission request and offered option.
- **Decide:** A typed decision permits the one fixture action, rejects it or cancels the task. Free text does not replace this decision.
- **Finish:** The demonstration asserts the expected file/state result, closes owned sessions and removes its temporary workspace.

An embedding application must preserve the actual request context and show the real offered operation. Authentication, UI honesty, executable trust, filesystem/network confinement and persistence are not supplied merely by this flow.
