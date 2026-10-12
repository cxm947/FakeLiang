# Orchestration batch 2

The baseline is e5dba09. The seven logical cells are planner, precheck, execute,
reconcile, verify, session, wrapup. They are named callables: planner belongs to
the outer graph and the other six belong to run_step. The physical graph keeps
planner / step / done, so step still calls run_step and recursion_limit remains
2*N + 3. Seven serial graph nodes per action would exceed that fixed limit.
Only StateGraph, conditional edges, compile, synchronous invoke and the official
SqliteSaver are used. No new resume path is introduced.

Execution order is E -> H -> V -> H: execute, delivery receipt and relay,
independent verification, proved credential/channel/position publication.
Even a failed relay result still reaches verification. Wrapup commits the final
step once; correction attempts do not append duplicate order/report entries.

The checkpoint state owns attempts. Planner counts are keyed by dispatch index
(len(order)); precheck, execute, verify and session counts are keyed by node id.
Faults and rejected planner answers share at most four calls, including the
first. The legacy executable-work nudge stays at the fourth call.
Execute has one four-attempt allowance across restarts and verification repairs.
No planner, precheck or restart entry resets a node's execution count.

The driver emits a private, runtime-owned correctable flag. run_step removes it
before building the public row. It can permit continuation after a model reply
failure or an unconcluded turn limit, or a repair after concrete verification
denial of output facts. False premises and honest unsatisfied conclusions stay
terminal. The driver also reads pending calls from its journal before granting
correction. Pending calls, rejected citations, generic UNKNOWN, conflicts and issued
or received session deliveries remain terminal. Feedback is a separate driver
argument recorded in existing history; the frozen task stays unchanged.
Failed prepared deliveries are retained only while an unissued correction can
continue; final failures run the existing cancellation path.

Precheck compares the selected node/card, host mapping, relevant current carrier
rows, and content hashes of credential source files and declared local assets
actually consumed. These observations live only in the current step's memory.
When they match, correction reuses prepared inputs and skips carrier probing and
asset preparation. Changed observations re-enter precheck and retain the execute
count. Existing frozen-manifest and credential-source mismatch refusals apply.

The internal stop_reason is converged, blocked, or budget_exhausted.
Convergence uses the existing plan_passed predicate and terminal fact evidence.
Blocked means no admissible work remains and evidence is still insufficient.
Exhaustion means planning/correction allowance or the outer action cap prevented
remaining work. A graph planner cannot accept a premature done while executable
unattempted work remains; it spends the same remaining four-call allowance.
The standalone planner compatibility entry keeps its existing early-done nudge.

Observable changes: a final [walk] stop_reason=... terminal line; checkpoint
attempts/cell/exhausted_nodes/stop_reason; controlled continuation for the narrow
failures above; existing reason_trace and journal feedback include those attempts.
No top-level plan_result.json field, planner wire field, or artifact path changes.
The SDK interface, once-only four extra transient retries, minute compensation
and fixed deadline remain as implemented in batch 1. A crash can repeat terminal
text; no live half-run recovery is enabled.

Dependency consumers:
- msgpack==1.1.0: RPC encoding in runtime.msfservice and test_carrier_matrix.
- paramiko==3.5.1: runtime.remote, including lab_round.py --remote verification.
- pymetasploit3==1.0.6: the runtime Metasploit RPC client.
The test/lab/rpc extras declare these consumers. Applying the generator resolves
binary wheels and missing transitive dependencies with acceptance pip, constrains
all existing 48 pins, and appends real wheel SHA-256 hashes. It can use an offline
wheelhouse. The resolved lock is concrete before installing or committing; review
the additional versions and hashes. No hashes are inferred from the snapshot.

scripts/install_git_hooks.py configures local ci.python and core.hooksPath.
scripts/hooks/pre-commit resolves the interpreter from git config ci.python.
Acceptance uses .venv312/Scripts/python.exe, with langgraph installed. Stage new
tracked files before the tree gate; it reads git ls-files. Three CI gates must
pass before and after the commit.

A pytest run leaves roughly 90 SQLite databases in the default private
checkpoints/ directory, one per temporary run-root. Lifecycle cleanup is batch 3;
batch 2 neither deletes checkpoints nor changes their lifetime.

Operational fact: if VMware GUI is stuck on a modal dialog, vmrun stop and
revertToSnapshot can hang indefinitely. That caused the lab's 300-second
timeouts; terminating the stuck GUI process clears the condition immediately.
The snapshot uses 300 seconds for stop/start and 900 for revert. This is a
documentation observation, not a change to lab timeouts or process handling.

Acceptance: preserve all original 992 assertions, add new scenarios, run pytest,
three gates, wheel/sdist/rebuilt-wheel/isolated-import checks, then the live
revert -> verify -> walk-221 launch -> accept sequence. Require VERDICT: PASSED,
12/12 and both terminal facts proved; read back the completed SQLite state.
Use state snapshots instead of sleeps while a launched round is still running.
The ignored tmp/launch_round.py and tmp/accept_run.py are caller-owned helpers,
absent from this snapshot; this patch does not replace them.

## Local wheel for pymetasploit3

`pymetasploit3==1.0.6` is not published on the package index this project resolves
against (the index stops at 1.0.4) and the upstream GitHub remote is unreachable
from the build host. The exact wheel that the acceptance environment already uses
is vendored next to the lock:

    requirements/wheels/pymetasploit3-1.0.6-py3-none-any.whl

Install the lock with the local wheel directory on the path so the recorded hash
still decides:

    python -m pip install --require-hashes --find-links requirements/wheels -r requirements/runtime-win-py312.lock

Every other pin resolves from the index. `pymetasploit3` is imported by
`runtime.msfservice`; dropping it would silently remove the Metasploit RPC carrier.
