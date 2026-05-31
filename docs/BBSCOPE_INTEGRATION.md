# bbscope Integration

Zero integrates `sw33tLie/bbscope` as a Go library, not as a shell command.

The analyzed upstream version exposes:

- `pkg/platforms.PlatformPoller`
- `pkg/platforms.PollOptions`
- `pkg/platforms/hackerone.NewPoller`
- `FetchProgramScope(ctx, handle, opts) scope.ProgramData`

This is a good fit because Zero can keep its own operational schema while reusing bbscope's platform-specific API handling.

## Current Adapter

`internal/scope/bbscope.go` currently supports HackerOne:

1. Build the HackerOne poller with `ZERO_H1_USERNAME` and `ZERO_H1_TOKEN`.
2. List handles using bbscope's `ListProgramHandles`.
3. Fetch structured scope for each handle.
4. Upsert programs and scope assets into `zero_programs` and `zero_scope_assets`.

## Why Not Reuse bbscope Tables Directly

bbscope's schema is optimized for scope aggregation and change tracking. Zero needs additional lifecycle tables for enumeration, probing, technology evidence, vulnerability matching, and reports. Keeping a Zero schema avoids coupling later stages to bbscope internals while preserving bbscope as a source adapter.

## Future Sources

bbscope already has pollers for Bugcrowd, Intigriti, YesWeHack, and Immunefi. They can be added as additional adapters using the same `PlatformPoller` interface.
