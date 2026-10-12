# Orchestration batch 3

Baseline: 4f2f38f. The outer graph remains planner / step / done with
recursion_limit=2*N+3 and durability="sync". The action timeout remains 60
seconds and one model call remains 90 seconds. There are no graph node thread
timeouts or additional graph features. Artifact paths and fields and the
planner decision / next_node_id / change_note contract remain unchanged.

## Saved boundaries

The original call journal owns request identity, intent, commit boundaries,
remaining deadline and receipt. Intent is saved before remote staging starts.
Staged blocks use existing call/receipt records with the parent association;
an incomplete staging block cannot disappear behind a later main intent.
Each commit records before_commit, committing and after_commit. A generated
receipt artifact may precede its journal registration. Recovery validates the
original call association and complete original artifact before adopting it.

Delivery plans save received, registering, registered, probing and probed
receipt phases. Receive uses session.list, the original before/after
difference, exact expected fields and the existing multi-match refusal.
A received session retains its original session id and UUID. Restart examines
the lower layer before continuing registration or probe. Query failure,
changed incarnation, multiple matches or missing association is unknown.

## Same-run entry and judgment

Add --resume to the original command with the identical --run-root and inputs.
The existing acquire_orchestrator lock prevents competing owners. Existing
checkpoints without --resume still fail loudly. Missing checkpoints and
finished runs cannot resume. A completed step whose output is saved in pending
writes must still finish the terminal node; it is not yet a finished run.

One JSON progress row shares the verified private checkpoint database and
stores interrupted attempt state. It is not an action log. Completed LangGraph
pending outputs outrank earlier progress. Resume restores state before invoking
the pending graph node; re-entry does not spend the same cell allowance twice.

Recovery has three judgments. Finished requires the original matched
call/receipt or proven original artifact. Not executed requires a saved
uncommitted boundary or an explicit lower-layer report of non-receipt.
Mid-commit, cancellation, timeout, failed queries, multi-match and lost
association are unknown. Unknown is never resent. A permitted continuation
uses the original id and only its remaining persisted deadline.

Each attempt persists its frozen parent source and channel/session/UUID
references. Restart rebuilds and checks that exact position. It refuses an
invalidated position. Only a new attempt may resolve a new parent.

## State and secret trace

Graph checkpoints and progress store values, ids and private references, never
clients, executors, connections or guards. No pickle fallback is enabled.
Tests route default checkpoint databases into a per-test temporary private
directory. Production retains the validated private database location and
closes the connection on every exit.

CLI RPC/model tokens and credential values are rebuilt from the original
private inputs. Frozen parent references exclude authentication values.
Restored connections obtain authentication only in memory. Request records,
transport artifacts and receipts apply the existing secret collection and
masking before durability. Recovery tests scan raw database/journal/receipt
bytes for supplied tokens and recursively check value-only state.

## Acceptance

tests/test_langgraph_recovery.py covers before commit; after commit before
receipt registration; generated sessions before registration; lower-layer
query failure, multiple matches and changed UUID; unknown refusal; invalidated
parents; preserved deadlines and attempt bookkeeping. One subprocess is
actually terminated after durable original call artifacts, then recovered
offline without another transport send. Existing assertions remain unchanged.
The owner declined a live same-run recovery acceptance round.

Stage new inventory paths before scripts/ci.py --label langgraph-batch3.
Require pytest, all three gates before and after commit, wheel, sdist, rebuilt
wheel and isolated import checks. Then use the normal live sequence:
lab_round.py revert --snapshot AGV-CLEAN-20261006-v2; lab_round.py verify;
tmp/launch_round.py walk-222; tmp/accept_run.py walk-222;
tmp/batch2_checkpoint.py walk-222.
scripts/check_recovery.py walk-222 --expect-converged 12 reports checkpoint and
saved boundary state without waiting. Require VERDICT: PASSED, 12/12, both
terminal nodes proved, order=12; route=done; stop_reason=converged.

Relay recovery uses strict original tunnel artifacts, the frozen parent UUID,
exact requested targets and the original owner's held listener leases. Partial,
ambiguous or released associations stay unknown. Framework exception writes
are masked by the non-pickle serializer as well as application snapshots.
Controlled model calls perform one HTTP send per saved call; a transport
timeout cannot trigger hidden HTTP retries. Explicit provider rejection (429)
remains a received fact and uses the existing attempt budget. Consumed private
source and local asset content hashes are rechecked before resuming an attempt.
Use the launcher's original --materials-dir with check_recovery.py; the lab
runner uses the TEMP/agv_materials private directory. No live recovery round.


## Session delivery correction (baseline 76f9c4e)

walk-228 node 19 produced exactly one exec fact: (pc1, system).
It failed while receiving more than one new callback on its own handler,
192.168.52.128:1083. Its before list already excluded old sessions.
The failure dictionary lacked attribution; missing node_id was consequently
reported as EXEC_DELIVERY_NODE_MISMATCH. This was not a foreign receipt.
Session IDs 3 and 4 have no completed receipt in that run.

walk-229 used the same graph-attribute binding and passed node 19 without
producing any delivery result for that node. All twelve proved nodes in that
run carry MODEL_CLAIM_NOT_MACHINE_VERIFIED. Nodes 7 and 26 additionally carry
VERIFY_QUOTE_NOT_IN_RECEIPT: the quoted line is absent from every receipt.
These observations do not establish stronger evidence in the passing run.
Neither reason's meaning or pass/fail semantics changes here.

Multiple exact fresh matches are repeat callbacks only when expected declares
a nonempty tunnel_local. First reception selects the lowest numeric session
ID (nonnumeric IDs follow, lexicographically). sessions still names only that
selection; repeat_callbacks records the other observed IDs, UUIDs, types,
hosts, handler addresses and platforms. Registration is called once, retaining
the existing one-carrier-per-host/privilege policy. Extras are observed, not
registered or stopped. Re-entry keeps the original received ID and UUID.
Contradictory fresh metadata on the same handler raises
SESSION_DELIVERY_HANDLER_CONFLICT; an overlapping active plan at the same
RPC endpoint and handler raises SESSION_DELIVERY_OWNER_CONFLICT. Cleaned and
not_started plans permit port reuse. UUID/exploit_uuid-only multi-match remains
SESSION_DELIVERY_AMBIGUOUS. Matching alone never establishes completion:
the existing registered carrier, fresh liveness and identity snapshot gates
still apply. No fallback callback is substituted after a frozen binding fails.

Valid-owner failures and no-match results carry the requested node and owner.
Malformed or legacy receipts with missing attribution produce the new
EXEC_DELIVERY_ATTRIBUTION_UNCONFIRMED, visible in verification assessments and
the printed run summary. Explicit foreign nodes/owners keep their mismatch
reasons. This step's attributed unfinished delivery produces the existing
EXEC_DELIVERY_NOT_COMPLETED; every EXEC_DELIVERY_* reason fails closed.
The frozen invalid-owner and missing-output return shapes are preserved.

walk-227 node 26 called SUID enumeration, received nonempty stdout, attempted
the identical request again, then claimed that the original stdout was empty.
The global executor prompt now requires every claim about a call to agree with
that call's recorded receipt, using the original receipt after a duplicate
refusal. No card changes. This is execution discipline, not automatic natural
language contradiction detection; its effectiveness needs live observation.
A hard conclusion check would require a structured observation assertion
(call ID, stream, property/value) and verification against the recorded bytes.
That larger contract change is proposed separately, not implemented here.

Machine-provable nodes need fact-specific deterministic checkers, exact
graph/target/environment/privilege binding, attributable current calls and
proof of the actual output. Identity checkers can support execCode; other
facts need their own checkers. Requiring machine proof now would reject
currently accepted model-only nodes and break frozen fallback acceptance.
The smallest intermediate option is an additive evidence-strength label
(model_claim or machine_checked), derived from checker provenance while
keeping the existing pass/fail rule. This patch does not implement that
owner-level product choice.

All prior test content, order and assertions remain byte-identical prefixes.
New scenarios are appended to the existing delivery test module. Notes are
appended here. No new tracked files or binaries: file_tree and gitattributes
need no changes. Stage the explicitly touched paths before the CI tree check.
Product README, planner wire, checkpoint isolation, atomic_write retry and
the three Path.write_text call-artifact boundaries remain untouched.


## Evidence reporting correction (baseline 3e8ec68)

An empty citation list is a valid completed model report when no calls are pending.
It establishes no output fact: MODEL_CLAIM_NOT_MACHINE_VERIFIED and the fact gate
continue to apply. Offered quotes still require an eligible, integrity-checked
receipt; marker requirements, delivery checks and unknown calls remain unchanged.

The executor receives a compact ledger of this step's calls and may inspect saved,
redacted stdout or stderr using a bounded local evidence read. Read offsets refer
to the saved redacted text. Reads do not dispatch, retry, settle or prove a target
action. Eight reads are available separately from the existing action-turn budget.
Repair and duplicate feedback include both streams; correction remains visible
when recent history is shortened.

Tongda expectations name the shipped AGV_L* stage outputs. The executor reports
delivery before runtime session registration. Verifier harvest is context unless
its source receipt is among the eligible supplied calls.

This round adds no repository files. Existing inventory blocks remain complete.
Append-only regression scenarios cover empty reports, invalid offered quotes,
saved stream reads, pending and marker guards, artifact integrity, duplicate
feedback, action budgets, delivery ordering and harvest provenance. Acceptance
still reports undecided facts and incomplete delivery still fails closed.
