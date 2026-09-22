# Windows console and registered-check execution

This is a **hosted-qualification candidate**, not evidence of a Windows pass.
The private NTFS state, source publication, recovery and pruning qualifications
remain independent. This change does not qualify native agent hosts, model calls,
paid-usage cancellation, a sandbox, or human presence.

## Console confirmation

The built-in terminal transport uses the actual inherited input and review-output
handles. `GetFileType` must identify character devices and `GetConsoleMode` must
succeed for **both** stdin and stderr. Input must retain processed, line-input
console mode. It does not open `CONIN$`, attach another console, trust `isTTY`,
accept an environment override, or reinterpret a callback as a terminal.
Redirecting either required handle fails closed.

The helper creates a random, first-instance, local-only named pipe, with a
protected current-user-only DACL. That pipe carries only a length-bounded review
and random challenge; it cannot carry a confirmation decision. The server checks
the client's OS process ID against the held parent process before reading.
The review is not written to a temporary file or placed in command-line arguments.
The pipe closes after the one framed request. stdin/stderr remain real console
handles; the private child stdout pipe carries correlated transport results.

`WriteConsoleW` displays the exact frozen broker rendering and a new 128-bit
challenge. Only an exact `ReadConsoleW` line can accept. Both the helper and
broker check the deadline/expiry; abort, EOF, unexpected output, failed native
calls and failed helper exit cannot issue a receipt. The backend retains its
120-second deadline, exact workspace/request/display binding, durable audit,
reopen and reviewed revocation behavior. Declining does not create runtime
state. A console or ConPTY is an OS transport, **not human-presence attestation**.
Automated input and same-account console injection are not claimed impossible.
An OS wait thread terminates a helper blocked in console/pipe input when its held
parent exits or the maximum confirmation lifetime elapses; no orphaned console
reader is intentionally left behind. The thread is signalled and joined before
its handles or memory are released.

## Registered trusted-local programs

Windows registration retains the existing immutable executable digest, argv,
working-directory, selected-control, source, check-definition and
verification-purpose authority bindings. Execution requires a canonical private
current-user NTFS working directory. It accepts an explicitly selected `.exe`,
not shell association or implicit PATH lookup.

The supervisor pins the working directory's observed volume/file identity and
every pathname ancestor without delete sharing. It opens the executable with
read-only sharing, checks its canonical final path, local NTFS volume, file type,
single link, unnamed stream and reviewed digest, and retains that same object
through execution. No check/use pathname reopen is substituted for the held
executable. Explicit `CreateProcessW` application name and CRT-quoted arguments
avoid shell interpretation. Only fixed OS environment entries are passed to the
check; the caller's credentials, `NODE_OPTIONS`, PowerShell module paths and
environment-supplied command paths are not copied into it.

A private unnamed Job Object has `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, without
either breakaway flag. `PROC_THREAD_ATTRIBUTE_JOB_LIST` assigns membership
**atomically with process creation**, avoiding the orphan interval between
suspended launch and a later job assignment. The child starts suspended, its
membership is checked, and only then is its initial thread resumed.
An explicit inherited-handle list contains only stdin/stdout/stderr, not the job,
parent, executable or directory handles. No fallback launches without the job
when the OS or an enclosing job refuses these attributes.

The root's exit alone is insufficient. `QueryInformationJobObject` must report
zero active processes, the held root process must be signalled, and both output
pipes must be drained before ordinary completion. Timeout and aggregate output
remain bounded at the registered limit (at most 300 seconds) and 1,000,000 bytes.
Cancellation requests job termination and observes it for at most one second.
Even observed termination remains an interrupted result, never passing evidence.
Unexpected supervisor death closes its sole job handle; the caller records
unknown, not assumed quiescence. Parent death is also observed through a held
process handle.
The claimed parent must still be alive and have an OS creation time preceding
the helper's own creation, so PID reuse after the caller exits is rejected.

These are **trusted local subprocesses, not confinement**. Ordinary
`CreateProcess` descendants inherit job membership, including detached console
children. Work delegated through WMI, services, brokers, remote systems or
same-account process manipulation is outside this guarantee. Such programs
must not be treated as covered by owned-job quiescence. The existing
`trusted-local-process` opt-in explicitly displays this limitation. SYSTEM,
machine administrators and the running user's trusted code remain within the
trust boundary. A timeout still persists `outcome-unknown / unconfirmed` and
blocks unchecked reuse, even when the owned job was observed empty.

## Platform and packaging boundary

The original interop is packaged under `assets/platform/`; there is no downloaded
native addon, compiler, execution-policy bypass, elevation or global install.
The launcher reuses the already-qualified fixed OS executable/ACL validation for
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, never cwd/PATH.
A dedicated read-only `validate-system-host` request completes only after those
OS executable and ancestor ACL checks. It does not use an empty private-entry
request or a dummy PID; the private-entry API still requires one to eight entries.
The native layout is for a 64-bit OS PowerShell process; other layouts fail
closed. Job-list creation requires Windows 10 / Server 2016 or newer. ConPTY
requires Windows 10 version 1809 / Server 2019 or newer. OS policy denying a
packaged script or these APIs leaves the capability unavailable.

The separate native-host process adapter is unchanged. Nothing in this adapter
claims termination of a native agent's descendants or hosted/paid work.

## Required hosted evidence

Use Node 24.21 on actual `windows-latest`, after `npm ci` and `npm run build`.
Keep the following independent selectors/jobs at no more than 15 minutes each;
no production deadline or assertion should be relaxed to make qualification pass.

```sh
node --test --test-concurrency=1 tests/windows-check-process.test.mjs
node --test --test-concurrency=1 --test-name-pattern="^Windows ConPTY exact challenge, replay, JSON refusal and redirected OS handles$" tests/windows-console.test.mjs
node --test --test-concurrency=1 --test-name-pattern="^Windows ConPTY deadlines and AbortSignal cannot issue late confirmation$" tests/windows-console.test.mjs
node --test --test-concurrency=1 --test-name-pattern="^Windows ConPTY real terminal receipts bind setup display, reopen and reviewed revocation$" tests/windows-console.test.mjs
node --test --test-concurrency=1 tests/windows-checks-integration.test.mjs
```

The original test-only ConPTY driver types real console input; synthetic input
is never called human attestation. It clears its own redirected standard-handle
table only during child creation, restores it in `finally`, and requires child
stdout/stderr to arrive through ConPTY, not the driver's protocol pipe. A
read-only child probe reports actual console handle types/modes. Driver and
child failures use distinct fixed frames with bounded static/numeric diagnostics;
unexpected output or a helper failure cannot substitute for a successful result.
The breakaway probe runs the fixed machine-trusted PowerShell host as an ordinary
descendant of the held canonical Node check, not as a claimed single-link
registered OS image. The same command must first succeed without the breakaway
flag before refusal with the flag counts as evidence.
The process cases launch real programs and
ordinary descendants, test output/timeout cancellation, parent death,
breakaway refusal and held-path replacement. The integration case uses the real
workflow, persistent callback authority, SQLite reopen and raw evidence,
including interrupted retention and blocked retry. Protocol-only tests run on
all platforms in `tests/windows-execution-protocol.test.mjs`; they and macOS
Windows skips do **not** qualify these native capabilities.

## Native API references

- [Job objects and their explicit broker/WMI limitation](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Process attributes, job list and explicit inherited handles](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [CreateProcessW application, command line and environment contracts](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [Console handle validation](https://learn.microsoft.com/en-us/windows/console/getconsolemode)
- [Standard-handle inheritance and console startup](https://learn.microsoft.com/en-us/windows/console/getstdhandle)
- [Creating a pseudoconsole session](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session)
