# Trace lifecycle validation

Build the solution with Visual Studio 2026/MSVC v145. The console test target uses the same production network engine with injected Win32/network operations; it requires no MFC or external network access.

```powershell
msbuild WinMTR.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64
.\Release_x64\TraceLifecycleTests.exe
```

Use Debug or Win32 for the other configurations. Windows CI builds and executes the suite in all four combinations. Assertions remain active in Release, and a 30-second process watchdog turns a lifecycle deadlock into a failing test.

The suite covers:

- 100 immediate Start/Stop cycles, repeated Stop, and stable process handle count.
- Immutable destination, packet size, interval, and DNS configuration.
- Interrupting a 60-second interval and draining outstanding probes.
- Stop during destination resolution, and rejection of restart until cleanup finishes.
- Pending reverse DNS, discarded results after cancellation, and DNS-disabled sessions.
- Failed resolution followed by a successful new session.
- Failed network initialization, stop-event creation, coordinator creation, partial probe startup, and DNS worker creation.
- An immediately failing probe worker, failed worker joins, failed completion polling, and failed stop/interval waits.
- Destruction while destination DNS, probes, or reverse DNS remain active; resource shutdown must wait for the operation to return.

## Probe outcome and pacing validation

The same target injects probe results and a per-worker monotonic clock. Scripted waits advance virtual time, so pacing assertions do not depend on wall-clock timing or a live network. Cases cover:

- Immediate local failures at configured intervals and the 100 ms local retry floor.
- Five-second timeouts with longer and shorter intervals, and no catch-up attempts.
- Actual elapsed duration instead of reply RTT, successful replies, and network errors.
- Zero and submillisecond intervals, upward rounding, and unsigned clock rollover.
- Immediate API error capture, stale last-error on success, and later Win32 calls overwriting last-error.
- Poisoned reply buffers after zero returns: no address, DNS work, RTT, or Received updates.
- Timeout/local-error classification, system-message and unknown-code fallbacks, and bounded messages.
- Recovery clearing active diagnostics and DNS hostnames surviving later local failures.
- Fatal API/buffer errors draining workers and allowing another session.
- Repeated Stop, destruction during a failed-probe interval, and interval-wait failure.

Sent retains its existing meaning of API attempts, including local failures; this change does not redefine packet-loss statistics. Active local failures appear separately in the status bar and include their numeric code. Retry spacing is at least the configured interval (rounded up to milliseconds), with a 1 ms minimum and a 100 ms minimum for local failures. Time already spent inside the attempt counts toward that spacing.

## Manual GUI smoke checks

Run under a standard Windows account with the executable being tested:

1. Trace `127.0.0.1`; verify results appear, Stop returns to idle, and Start works again.
2. Close an active trace with Exit, the title-bar Close button, and Escape in separate runs.
3. Trace a nonexistent `.invalid` hostname; verify one error appears and the controls return to idle.
4. On a controlled DNS test network, delay destination and reverse lookups. Stop/Close must leave the window responsive, display the DNS waiting message, and finish only after DNS returns.
5. Repeat on Windows 7 and current Windows, for Win32 and x64 where available.

Windows 7 support uses synchronous DNS on background workers and retains the existing five-second ICMP request timeout. DNS itself has no guaranteed shutdown deadline. Compiling with `WINVER`/`_WIN32_WINNT=0x0601` does not prove runtime compatibility; Windows 7 and live stalled-DNS smoke tests must be recorded separately from injected tests.

For probe pacing, also trace an unreachable destination and exercise Stop/Close while a probe is outstanding. On a controlled network, induce a local failure and restore connectivity; verify the status bar reports the failure without replacing the hostname and clears after recovery. Invalid API/handle/buffer outcomes are injected in native tests rather than manufactured by modifying production networking state.
