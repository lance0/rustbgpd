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

If the receipt was written, it says so (the next step covers when it was not):

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

`error_class` tells you how far it got. `activation` (the case this runbook
walks) means the candidate was rendered, `current` was moved, and the
activation command started. `transport`, `status`, or `control_body` mean the
*lock request itself* was ambiguous: nothing was rendered or moved, `current`
is unchanged, and you can go straight to steps 3 and 5. A plain `activate`
leaves no journal and holds no upstream lock — skip step 3.

While the fence stands, `resume` and every new `run` or `activate` answer with
the same exit 5 line and touch nothing; `resume` has no action for this phase.

## 1. Is the candidate live and healthy, live and broken, or down?

The helper's settlement test is `rbgp health` plus `rbgp config diff` against
the candidate; run the same two by hand. The generation's `config.toml` names
its policy files relatively, and the daemon resolves those against its own
working directory, so diff a copy with the paths rewritten to the live
`current/` prefix (exactly what the helper compares):

```bash
rbgp --addr $UDS health
umask 077
sed 's#"policy/#"'"$STATE"'/current/policy/#' $STATE/current/config.toml > $STATE/.compare.toml
rbgp --addr $UDS config diff $STATE/.compare.toml; echo "rc=$?"
rm $STATE/.compare.toml
```

**Live and equal** (the reload landed; the helper only ran out of settle
budget, or the receipt write failed afterwards):

```text
Status:  healthy
Uptime:  00:00:05
Peers:   0
Routes:  0
No changes.
rc=0
```

**Live but still on the previous generation** (the activation command ran and
failed without reloading — a sudoers denial, a wrong unit name — or the daemon
rejected the reload). The diff lists exactly what the daemon is missing:

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
previous generation. If the two generations differ only in policy files this
comparison reads them through `current/`, so re-point first (step 2) and diff
again. The daemon log has no `config reload complete` line for the attempt.

**Down** (a restart took the old process out and the new one never came up):

```text
Error: cannot reach rustbgpd at unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock (socket does not exist)
  hint: is the daemon running? if it uses a different endpoint, pass -s or set RUSTBGPD_ADDR
rc=1
```

`healthy: false` from `rbgp --json health`, or a diff that errors on a reachable
daemon, is "live and broken": treat it as the down case and prefer the previous
generation.

## 2. Keep the candidate or roll back

Pick by what step 1 showed. Neither `resume` nor `activate` will do this for
you: `resume` refuses the `manual_recovery` phase, `activate` refuses while the
fence stands and refuses again ("current runtime is not known-good") until
`current` and the daemon agree. Re-pointing `current` is not currently
supported as a command; the manual procedure is an atomic symlink swap, using
the `previous_generation` value from the receipt:

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

Then repeat step 1 until it reads `No changes.` / `rc=0` — that is the
"current and daemon agree" state every later helper run requires:

```text
Status:  healthy
No changes.
rc=0
```

Whichever you chose decides the callback in step 3: kept means `updated`,
rolled back means `release-update-lock`.

## 3. Release the retained IXP Manager update lock (lifecycle runs only)

The helper acquired the router's update lock and, because the activation
effect is uncertain, delivered no callback. IXP Manager still shows the router
mid-update (`last_update_started` newer than `last_updated`), and any run after
you clear local state in step 5 stops at the lock:

```text
rs-config-render: IXP Manager lifecycle: IXP Manager update lock was not acquired
```

(exit 2, from a 423 Locked). Releasing it is not currently supported by
`rs-config-render`; the manual procedure is to deliver, yourself, the callback
the helper would have sent — the same v7.4 endpoint, same handle, same API key
in the same header. Keep the key out of argv with a mode-0600 header file:

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

`release-update-lock` resets `last_update_started` to `last_updated`; `updated`
stamps a new `last_updated`. Either way the lock is free. Delivery is
at-least-once by design, so sending one twice is harmless; sending the wrong
one is not — `updated` tells IXP Manager a configuration is live that you
rolled away from.

## 4. The activation receipt may be absent or stale

Exit 5 also covers "the receipt's final write or directory sync failed", so
before re-running anything check whether `activation-receipt.json` describes
this attempt at all:

```bash
grep -E '"(status|candidate_sha256)"' $STATE/activation-receipt.json; readlink $STATE/current
```

It describes this attempt when `candidate_sha256` equals the generation
`current` pointed at when you arrived. A receipt naming an older generation
(or `"status": "activated"` for the previous run, or no file) is stale: the
write never landed, and `previous_generation` is then whatever generation
`current` pointed at *before* the failed run — confirm it by the diff in step 1
rather than the receipt. After a rollback the receipt is stale by construction
(it still names the candidate). Leave it alone: the helper never reads it back
— it verifies the render receipt inside each generation instead — and the next
successful run rewrites it.

## 5. When automation may resume

The fence and the journal are the helper's own proof that a human has not yet
decided; clearing them is not currently supported as a command. The manual
procedure, once steps 1–4 are done and step 1 reads `No changes.`:

```bash
rm $STATE/ixp-manager-lifecycle.json $HOST/ixp-manager-host-fence.json && sync $STATE $HOST
ls -la $HOST
```

```text
-rw------- 1 rustbgpd rustbgpd    0 Aug 22 15:01 ixp-manager-host.lock
```

Remove both as a pair. The fence belongs to the handle named inside it; a
lifecycle for another handle sharing the host-state directory is refused while
it stands. Then fix the cause (the sudoers rule, the unit name, the settle
budget, the crashed restart) and run the lifecycle once by hand with the
production arguments before handing back to cron:

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
