# test-derive — TEST-ONLY derivation wrapper

## Why this exists

Running `deaddrop send` / `recv` against a self-hosted relay requires
several out-of-band values per machine: the URL prefix (`CADDY_PREFIX`),
`DEPLOY_SECRET`, `WRITE_TOKEN`, plus a capsule passphrase. For a
two-laptop personal test loop, copying all of those between machines
is painful.

`test-derive` collapses everything to a single memorable passphrase
plus the relay hostname. Run the wrapper with the same phrase + host
on laptop A and laptop B and both regenerate identical values
deterministically — including the URL prefix.

## How to use

Build (from repo root):

    make test-derive

Quick send/recv (set `DEADDROP_SITE_ADDR` first — the relay must be
provisioned with a `CADDY_PREFIX` derived from the same phrase):

    export DEADDROP_SITE_ADDR="your-relay.example"

    # On sender machine — prompts for passphrase once:
    ./tools/test-derive/quick-send.sh /path/to/capsule file.txt

    # On receiver machine — same passphrase:
    ./tools/test-derive/quick-recv.sh /path/to/capsule received.txt

The examples above assume a **bootstrap** capsule (made with
`quick-bootstrap.sh`), where content-layer E2E is automatic. With a
plain **`keygen`** capsule there is no per-pair identity, so `--require-e2e`
(default-on) fails with exit 22. Append `--no-require-e2e` — the wrappers
forward any trailing flags to `deaddrop`:

    ./tools/test-derive/quick-send.sh /path/to/capsule file.txt --no-require-e2e
    ./tools/test-derive/quick-recv.sh /path/to/capsule --no-require-e2e received.txt

For `quick-recv.sh`, put flags **before** the output path — `recv` stops
parsing flags at the first positional argument.

`DEADDROP_RELAY_URL` is still accepted as a fallback when you want to
target a relay whose `CADDY_PREFIX` was provisioned independently.

Non-interactive (CI / scripting):

    eval "$(./tools/test-derive/test-derive \
        --phrase-fd 3 \
        --site-addr "$DEADDROP_SITE_ADDR" \
        3<<<'my test phrase')"

    # All six env vars are now set:
    #   DEADDROP_RELAY, DEADDROP_DEPLOY_SECRET, DEADDROP_WRITE_TOKEN,
    #   DEADDROP_BOOTSTRAP_PA, DEADDROP_CAPSULE_PASSPHRASE,
    #   DEADDROP_CADDY_PREFIX

Bootstrap pairing:

    ./tools/test-derive/quick-bootstrap.sh /path/to/capsule --role=initiator
    # (on the other machine)
    ./tools/test-derive/quick-bootstrap.sh /path/to/capsule --role=responder

## Why this is NOT for production

1. **Hardcoded salt** + memorable phrase = offline brute-forceable if the
   attacker has the binary AND a sample of derived output.
2. **Deterministic derivation** breaks any forward-secrecy story.
3. **One phrase compromise** = total compromise of all derived secrets.

Production replacements are planned: keyring-backed passcache and a
local profile file; both are tracked as future work.
