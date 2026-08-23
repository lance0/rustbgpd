# Runbook: activation exit 5 (manual recovery)

**When this is you:** `rs-config-render activate` or
`rs-config-render ixp-manager-lifecycle run` returned exit 5 — the activation
command started, but the helper could not prove the daemon settled on the
candidate — and every later run (and `resume`) also returns exit 5. Nothing
self-heals here by design: the helper refuses to guess which configuration is
live, and the IXP Manager update lock stays held until a person decides. Work
top to bottom.

Paths below are the [`rs-config-render`](../../tools/rs-config-render/README.md)
example layout for handle `rs1-ipv4` — substitute yours. Run everything as the
`rustbgpd` service identity that owns the private state. The outputs were
captured from a real daemon against a loopback stand-in of the IXP Manager v7.4
router API; only `--ixp-origin` differs from a production invocation.

```bash
STATE=/var/lib/rustbgpd/rs1-ipv4/activation
HOST=/var/lib/rustbgpd/ixp-manager-host
UDS=unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock
```

## How to recognise it

The exit code is 5 and stderr carries one of two lines:

```text
rs-config-render: IXP Manager lifecycle: manual recovery required; upstream lock retained
rs-config-render: activation: recovery required; inspect private activation state
```

Then read the state with `status`. It takes the same binding flags as
`activate`, changes nothing (no lock, nothing written), and with `--rbgp` runs
the helper's own settlement probe against the daemon:

```bash
rs-config-render status --router-handle rs1-ipv4 \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 --state-dir $STATE \
  --host-state-dir $HOST --rbgp-addr $UDS --rbgp /usr/bin/rbgp
```

```text
fence: present
journal: present
phase: manual_recovery
callback: none
callback_attempts: 0
activation_outcome: recovery_required
error_class: activation
lock: retained
current: generations/53fa45222b96917cac847a870e16a6a29da9195adf5db717a4bd3b305f9e1d9c
candidate: generations/53fa45222b96917cac847a870e16a6a29da9195adf5db717a4bd3b305f9e1d9c
current_is_candidate: yes
advisory_receipt: matches-current
advisory_receipt_status: recovery_required
advisory_receipt_previous_generation: generations/55de8d9cf767c58ce9b197129f69b2a776aa54bad6542385c4e5be924d8e460a
daemon: healthy
runtime_equals_current: no
```

`fence: present` is the owner fence standing in the shared host-state
directory: while it stands, `resume` and every new `run` or `activate` answer
with the same exit 5 line and touch nothing (`resume` has no action for this
phase). `current_is_candidate: yes` says `current` was moved onto the candidate
and `advisory_receipt_previous_generation` names what was live before.

`error_class` tells you how far it got. `activation` (the case this runbook
walks) means the candidate was rendered, `current` was moved, and the
activation command started; `lock: retained` means the IXP Manager update lock
is still owed. `transport`, `status`, or `control_body` mean the *lock request
itself* was ambiguous: the output then reads `activation_outcome: none`,
`lock: unknown`, `candidate: none`, `current_is_candidate: no` — nothing was
rendered or moved — and you can go straight to steps 3 and 5. A plain
`activate` leaves no journal (`journal: absent`, `lock: none`) and holds no
upstream lock — skip step 3.

The activation receipt is advisory: `advisory_receipt: stale` or `absent`
means its final write never landed (step 4). The journal, the fence, and the
generation tree are the state; the receipt is not.

## 1. Is the candidate live and healthy, live and broken, or down?

The last two `status` lines are the helper's own settlement test. It runs
`rbgp health` first and only when that explicitly reports healthy does it stage
and run `rbgp config diff` against the `current` generation, with policy paths
rewritten to the live `current/` prefix (exactly what the helper compares).
Read them together:

| `daemon` | `runtime_equals_current` | Meaning |
|---|---|---|
| `healthy` | `yes` | **Live and equal**: the reload landed; the helper only ran out of settle budget, or the receipt write failed afterwards. |
| `healthy` | `no` | **Live but still on the previous generation**: the activation command ran and failed without reloading (a sudoers denial, a wrong unit name) or the daemon rejected the reload. The daemon log has no `config reload complete` line for the attempt. |
| `healthy` | `unknown` | **Comparison inconclusive**: staging failed, or `config diff` could not start, timed out, exited 1, or returned another unexpected status. Do not infer equal or different, or that the diff completed. |
| `unreachable` | `unknown` | **Down**: a restart took the old process out and the new one never came up. The helper did not run `config diff`. |
| `unhealthy`, or `invalid` | `unknown` | **Live and broken or an invalid health response**: the helper did not run `config diff`; treat it as the down case and prefer the previous generation. |

To see *what* the daemon is missing in the second row, or to confirm it runs
the previous generation, run the diff by hand
([appendix A](#a-reading-the-state-by-hand)). If the two generations differ
only in policy files that comparison reads them through `current/`, so
re-point first (step 2) and diff again.

## 2. Keep the candidate or roll back

Pick by what step 1 showed. Neither `resume` nor `activate` will do this for
you: `resume` refuses the `manual_recovery` phase, `activate` refuses while the
fence stands and refuses again ("current runtime is not known-good") until
`current` and the daemon agree. The `recover` verbs do it. Every verb takes the
binding flags `status` takes, is a dry run unless `--apply`, prints the exact
steps it would perform, refuses (exit 2, nothing changed) outside this state,
and — for a lifecycle run, whose journal owes the upstream lock — needs the
same connection `resume` takes:

```bash
BIND="--router-handle rs1-ipv4 --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --state-dir $STATE --host-state-dir $HOST --rbgp-addr $UDS"
IXP="--ixp-origin https://ixp.example.net --api-key-file /var/lib/rustbgpd/ixp-manager/api-key"
```

Without `$IXP` a journal-holding recovery refuses before planning (`lifecycle
journal owes the upstream lock; pass --ixp-origin and --api-key-file`); a
plain `activate` exit 5 has no journal and needs no connection.

**Keep the candidate** (step 1 read `daemon: healthy` and
`runtime_equals_current: yes`):

```bash
rs-config-render recover keep-current --rbgp /usr/bin/rbgp $BIND $IXP
```

```text
recover keep-current: probe: daemon healthy, runtime equals current
recover keep-current: write activation receipt: status kept, candidate 53fa45222b96917cac847a870e16a6a29da9195adf5db717a4bd3b305f9e1d9c, previous generations/55de8d9cf767c58ce9b197129f69b2a776aa54bad6542385c4e5be924d8e460a
recover keep-current: deliver updated callback to https://ixp.example.net for rs1-ipv4 (attempt 1)
recover keep-current: remove lifecycle journal
recover keep-current: remove host fence
recover keep-current: dry run — 5 step(s) planned; pass --apply to perform them
```

Add `--apply` to perform exactly those steps; the last line becomes `recover
keep-current: applied 5 step(s)` and the exit is 0. The verb is health-gated:
when the probe does not read healthy and equal it refuses with `daemon is not
settled on current; fix the daemon by hand or pass --force`. In the "live on
the previous generation" and "down" rows that means either running your
activation command by hand (`reload-or-restart` starts a stopped unit on
`current`) and re-running `keep-current`, or rolling back. `--force` declares
the candidate kept regardless (the probe line then ends `(overridden by
--force)` and the receipt records `runtime_equal: false`).

**Roll back** (step 1 read live-on-previous, down, or broken):

```bash
rs-config-render recover rollback --rbgp /usr/bin/rbgp \
  --activation-command /usr/bin/sudo --activation-arg=-n --activation-arg /usr/bin/systemctl \
  --activation-arg reload-or-restart --activation-arg rustbgpd@rs1-ipv4 $BIND $IXP
```

```text
recover rollback: re-point current generations/53fa45222b96917cac847a870e16a6a29da9195adf5db717a4bd3b305f9e1d9c -> generations/55de8d9cf767c58ce9b197129f69b2a776aa54bad6542385c4e5be924d8e460a, run `/usr/bin/sudo -n /usr/bin/systemctl reload-or-restart rustbgpd@rs1-ipv4`, settle within 30s
recover rollback: deliver release-update-lock callback to https://ixp.example.net for rs1-ipv4 (attempt 1)
recover rollback: remove lifecycle journal
recover rollback: remove host fence
recover rollback: dry run — 4 step(s) planned; pass --apply to perform them
```

The target is the receipt's `previous_generation` when step 1 read
`advisory_receipt: matches-current`; otherwise pass `--to
generations/<digest>` — the generation `current` pointed at before the failed
run, confirmed by the hand diff in appendix A. Rollback goes through the same
publish → activation command → settle path as a first activation (not a bare
symlink swap) and writes the activation receipt as `rolled_back`. If the daemon
does not settle on the target within `--settle-seconds`, the verb exits 5
(`rollback did not settle`): `current` is re-pointed, the receipt reads
`recovery_required`, fence and journal stay — run `status` again and work from
step 1. It refuses when the journal shows no candidate was activated (the
lock-ambiguous case: use `release-lock --rolled-back` and `clear`), when the
target is the current generation, or when the target is not a published
generation.

In both verbs the callback is the one step that can fail on its own (step 3):
the local work is then done, the exit is 5, and the message names the retry
(`updated callback was not delivered; upstream lock retained — retry with
recover release-lock --kept`, or the `--rolled-back` twin). With a
lock-ambiguous journal `keep-current` delivers `release-update-lock` instead of
`updated`, since nothing was updated.

Then `status --rbgp` reads `daemon: healthy` and `runtime_equals_current:
yes` — that is the "current and daemon agree" state every later helper run
requires.

## 3. Release the retained IXP Manager update lock (lifecycle runs only)

The helper acquired the router's update lock and, because the activation
effect is uncertain, delivered no callback. IXP Manager still shows the router
mid-update (`last_update_started` newer than `last_updated`), and any run after
you clear local state in step 5 stops at the lock:

```text
rs-config-render: IXP Manager lifecycle: IXP Manager update lock was not acquired
```

(exit 2, from a 423 Locked). `keep-current` and `rollback` deliver the
callback themselves; `release-lock` is for when that delivery failed, or when
you resolved step 2 by hand ([appendix B](#b-the-hand-procedures)). It
delivers one callback, standalone and retryable, and touches nothing else:

```bash
rs-config-render recover release-lock --kept $BIND $IXP          # kept the candidate
rs-config-render recover release-lock --rolled-back $BIND $IXP   # rolled back, or nothing was activated
```

```text
recover release-lock: deliver updated callback to https://ixp.example.net for rs1-ipv4 (attempt 2)
recover release-lock: mark the upstream lock released in the lifecycle journal
recover release-lock: dry run — 2 step(s) planned; pass --apply to perform them
```

With `--apply` the intent is journaled before the request (`status` shows
`callback` and `callback_attempts`); a failed delivery exits 5 and the same
command retries it. Once delivered, `status` reads `lock: released`, and
`keep-current`/`rollback` defer to `clear`. `release-update-lock` resets
`last_update_started` to `last_updated`; `updated` stamps a new
`last_updated`. Either way the lock is free. Delivery is at-least-once by
design, so sending one twice is harmless; sending the wrong one is not —
`updated` tells IXP Manager a configuration is live that you rolled away from.

## 4. The activation receipt may be absent or stale

Exit 5 also covers "the receipt's final write or directory sync failed", so
the `advisory_receipt` line of `status` tells you whether the receipt describes
this attempt: `matches-current` (its `candidate_sha256` equals the generation
`current` pointed at when you arrived) or `stale`/`absent` (the write never
landed; `previous_generation` is then whatever generation `current` pointed at
*before* the failed run — confirm it by the hand diff in appendix A, and pass
it to `rollback --to`). `keep-current` and `rollback` rewrite the receipt
(`kept`, `rolled_back`) so it describes what you decided; the helper never
reads it back — it verifies the render receipt inside each generation
instead.

## 5. When automation may resume

The fence and the journal are the helper's own proof that a human has not yet
decided. `keep-current` and `rollback` remove both as their last steps; `clear`
does only that, for when you released the lock with `release-lock` or did
step 2 by hand:

```bash
rs-config-render recover clear $BIND
```

```text
recover clear: remove lifecycle journal
recover clear: remove host fence
recover clear: dry run — 2 step(s) planned; pass --apply to perform them
```

`clear` accepts exactly two states: no lifecycle journal at all (a plain
`activate` exit 5, or a journal you removed by hand), or a journal whose
callback `release-lock` delivered (`status` reads `lock: released`). Any other
journal means the upstream lock is still owed and it refuses (`upstream lock
still owed; run recover keep-current, recover rollback, or recover release-lock
first`). It does not probe the daemon: make sure step 1 reads healthy and equal
first, because every later helper run requires `current` and the daemon to
agree. The fence belongs to the handle named inside it; a lifecycle for another
handle sharing the host-state directory is refused while it stands.

Then fix the cause (the sudoers rule, the unit name, the settle budget, the
crashed restart) and run the lifecycle once by hand with the production
arguments before handing back to cron:

```text
IXP Manager lifecycle activated
```

(or `IXP Manager lifecycle noop` when IXP Manager's data already matches what
you kept; a hand `activate` prints `activation activated`). Exit 0 means the
lock was taken and released in one pass and `current` and the daemon agree;
cron may resume.

A wrapper around that cron run can rely on 5 meaning "a human is needed", and
on a 2 whose message is `IXP Manager update lock was not acquired` meaning step
3 was skipped. Every `rs-config-render` subcommand shares one exit-code table
(the [tool README](../../tools/rs-config-render/README.md#exit-codes)), so a
wrapper can branch on the code alone: 7 is always the benign, already-released
lifecycle rollback and 4 is always arouteserver shape drift.

## A. Reading the state by hand

Everything `status` prints comes from four files; when the binary is not at
hand, or to see the diff itself, read them directly.

`current` points at the candidate generation, not the one that was live
before, and an owner fence stands in the shared host-state directory:

```bash
readlink $STATE/current
ls -la $HOST
```

```text
generations/53fa45222b96917cac847a870e16a6a29da9195adf5db717a4bd3b305f9e1d9c
-rw------- 1 rustbgpd rustbgpd  274 Aug 22 15:01 ixp-manager-host-fence.json
-rw------- 1 rustbgpd rustbgpd    0 Aug 22 15:01 ixp-manager-host.lock
```

If the receipt was written, it says so:

```bash
grep -E '"(status|candidate_sha256|previous_generation|runtime_equal)"' $STATE/activation-receipt.json
```

```text
  "candidate_sha256": "53fa45222b96917cac847a870e16a6a29da9195adf5db717a4bd3b305f9e1d9c",
    "runtime_equal": false
  "previous_generation": "generations/55de8d9cf767c58ce9b197129f69b2a776aa54bad6542385c4e5be924d8e460a",
  "status": "recovery_required",
```

A lifecycle run additionally leaves a journal with the lock still owed:

```bash
grep -E '"(phase|callback|activation_outcome|error_class)"' $STATE/ixp-manager-lifecycle.json
```

```text
  "phase": "manual_recovery",
  "callback": null,
  "activation_outcome": "recovery_required",
  "error_class": "activation"
```

The settlement test by hand is `rbgp health` plus `rbgp config diff` against
the candidate. The generation's `config.toml` names its policy files
relatively, and the daemon resolves those against its own working directory,
so diff a copy with the paths rewritten to the live `current/` prefix:

```bash
rbgp --addr $UDS health
umask 077
sed 's#"policy/#"'"$STATE"'/current/policy/#' $STATE/current/config.toml > $STATE/.compare.toml
rbgp --addr $UDS config diff $STATE/.compare.toml; echo "rc=$?"
rm $STATE/.compare.toml
```

**Live and equal** (`runtime_equals_current: yes`):

```text
Status:  healthy
Uptime:  00:00:05
Peers:   0
Routes:  0
No changes.
rc=0
```

**Live but still on the previous generation** (`runtime_equals_current: no`);
the diff lists exactly what the daemon is missing:

```text
Status:  healthy
Reload-applied changes:

  Neighbors:
    ~ 10.1.0.10:
        max_prefixes_ipv4: 900 → 1000  [hot-applied]

Plan: 1 to change · no session resets expected
rc=2
```

Confirm by diffing the previous generation from the receipt the same way
(`sed … $STATE/generations/<previous_generation>/config.toml`, still rewriting
to the `current/` prefix): `No changes.` / `rc=0` means the daemon runs the
previous generation.

**Down** (`daemon: unreachable`):

```text
Error: cannot reach rustbgpd at unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock (socket does not exist)
  hint: is the daemon running? if it uses a different endpoint, pass -s or set RUSTBGPD_ADDR
rc=1
```

`healthy: false` from `rbgp --json health` (`daemon: unhealthy`), or a diff
that errors on a reachable daemon, is "live and broken".

## B. The hand procedures

What the `recover` verbs do, by hand, for a host without the binary or a state
the verbs refuse (an unreadable or foreign fence or journal: inspect who wrote
them before removing anything).

**Re-point `current`** (rollback) is an atomic symlink swap using the
`previous_generation` value from the receipt, followed by your activation
command:

```bash
PREV=generations/55de8d9cf767c58ce9b197129f69b2a776aa54bad6542385c4e5be924d8e460a
ln -s $PREV $STATE/.current.rollback && mv -T $STATE/.current.rollback $STATE/current && sync $STATE
readlink $STATE/current
```

```text
generations/55de8d9cf767c58ce9b197129f69b2a776aa54bad6542385c4e5be924d8e460a
```

| Step 1 said | Keep the candidate | Roll back |
|---|---|---|
| Live and equal | Nothing to do to the daemon. | Re-point, then run your activation command by hand (the exact `--activation-command`/`--activation-arg` line, normally `systemctl reload-or-restart rustbgpd@rs1-ipv4`). |
| Live on the previous generation | Run your activation command by hand. | Re-point only; the daemon already runs it. |
| Down | Run your activation command by hand (`reload-or-restart` starts a stopped unit on `current`). | Re-point, then run your activation command by hand. |

Whichever you chose decides the callback: kept means `updated`, rolled back
means `release-update-lock`.

**The callbacks** are the same v7.4 endpoints, same handle, same API key in
the same header. Keep the key out of argv with a mode-0600 header file:

```bash
umask 077
printf 'X-IXP-Manager-API-Key: %s\n' "$(cat /var/lib/rustbgpd/ixp-manager/api-key)" \
  > /var/lib/rustbgpd/ixp-manager/api-key-header
# rolled back:
curl -sS -X POST -H @/var/lib/rustbgpd/ixp-manager/api-key-header -w '\nHTTP %{http_code}\n' \
  https://ixp.example.net/admin/api/v4/router/release-update-lock/rs1-ipv4
# kept the candidate instead:
curl -sS -X POST -H @/var/lib/rustbgpd/ixp-manager/api-key-header -w '\nHTTP %{http_code}\n' \
  https://ixp.example.net/admin/api/v4/router/updated/rs1-ipv4
```

```text
{"last_update_started": "2026-08-22T15:05:00+00:00", "last_update_started_unix": 1787411100, "last_updated": "2026-08-22T15:05:00+00:00", "last_updated_unix": 1787411100}
HTTP 200
```

**Clearing** is removing the fence and the journal as a pair:

```bash
rm $STATE/ixp-manager-lifecycle.json $HOST/ixp-manager-host-fence.json && sync $STATE $HOST
ls -la $HOST
```

```text
-rw------- 1 rustbgpd rustbgpd    0 Aug 22 15:01 ixp-manager-host.lock
```

After a hand rollback the receipt is stale by construction (it still names the
candidate); leave it alone, the next successful run rewrites it.

## What this runbook does not cover

- Exit 6 (one callback pending): run `ixp-manager-lifecycle resume`; it replays
  only that callback.
- Exit 7 (the activation command never started): nothing to recover, `current`
  was restored and the lock released.
- An unreadable or foreign fence or journal (wrong mode, symlink, another
  handle's binding, unparseable JSON): the helper exits 5 for those too;
  inspect who wrote them before removing anything.
- IXP Manager's own state beyond the two callbacks, a `pause_updates` router,
  or an API key that has since expired.
- The arouteserver refresh loop (`rsync` + SIGHUP); it has no activation state
  and no exit 5.
