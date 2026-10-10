# Changelog

## 0.6.44

### Added

- **`artzain connect openshell upgrade`.** Moves a connected gateway to
  the newest artzain the signed OpenShell compatibility manifest lists with
  the gateway's installed OpenShell release, by running that release's
  connect script (no new token). It reads the manifest from the newest
  `compat-v<serial>` release of CogNEXUSlabs/cognexus-tools and verifies
  its signature with cosign v2.6.5 against the identity of that
  repository's `openshell-compat.yml` at a `compat-v` tag. cosign is
  downloaded once, by a SHA-256 pinned in artzain, into the sidecar's
  state folder, and checked again before each run. It refuses a manifest
  whose serial is not its tag's, or is lower than the last one this host
  read, and a connect script that is not the one the manifest names by its
  SHA-256. `--check` says what it would do and changes nothing; `--to
  <version>` names a listed, newer release. The new `up` runs the
  self-test again: one denied decision, billed like any other.

## 0.6.43

### Added

- **`artzain connect openshell up` installs OpenShell on a host that has
  none.** It used to stop with "openshell is not on PATH". Now, on a
  systemd host with dpkg or rpm, it offers to install NVIDIA's packages of
  the release this artzain binds (0.1.2): the deb, or the three rpms, for
  the host's architecture. Each package is downloaded from NVIDIA's GitHub
  release and checked against a SHA-256 this release pins before anything
  runs as root. It then installs them with apt-get (or dpkg, dnf, yum,
  zypper, rpm) under sudo, starts the `openshell-gateway` user service and
  registers it with the `openshell` CLI. At a terminal it asks first; with
  `--install-openshell` it does not ask. Without a terminal and without the
  option, it prints the same steps as commands and stops, with no token
  spent. `remove` leaves OpenShell installed.
- **`up` prints the self-test's receipt link**:
  `<engine>/dashboard.html?receipt=<decision id>`, which opens the sealed
  leaf in the dashboard's audit drawer after a sign-in if need be. `status`
  shows it as `self_test_receipt`, and `doctor` names it beside the
  self-test's decision.

## 0.6.42

### Added

- **OpenShell break-glass: `artzain connect openshell break-glass`.** While
  ArtzAIn cannot answer, every governed write fails closed. The gateway's
  host user can now open a window of 1 to 240 minutes, with a reason
  (`--minutes N --reason "..."`; `--close` ends it early). In it, a write
  the engine gave no answer for, or a 5xx, goes through, journaled first:
  a write that cannot be journaled is refused. A deny, a review, a rate
  limit, a refused credential (a 4xx), a certificate that does not verify
  and a gateway-wide write still refuse. Only the host opens a window: the
  sidecar's loopback route (`/artzain/break-glass`), with its token. It ends
  on its own, by the wall clock or the monotonic clock. The hash-chained
  journal (`breakglass-journal.json` in the sidecar's state folder) goes to
  the engine's gateway route in order once the engine can be reached, and
  each entry becomes a flagged receipt; each window, a Review queue item.
  `status` shows the open window.

### Fixed

- **The package metadata names the license as the SPDX expression
  `Apache-2.0`.** It used to copy the whole license file into the
  `License` field, so scanners such as deps.dev reported the license as
  non-standard. The license text still ships as `LICENSE`.
- **A caller the OpenShell sidecar refuses reads its 401.** The sidecar
  answered before reading the request's body, and the caller could see the
  connection reset instead. It now reads the body (up to 1 MB) first.

## 0.6.41

### Fixed

- **A sidecar that holds a gateway credential answers its loopback routes
  only to a caller with its token.** The sidecar `artzain connect openshell
  up` installs listens on 127.0.0.1 beside its Unix socket, and wrote no
  `OPENSHELL_SIDECAR_TOKEN`, so its routes answered any local caller, as
  the gateway. Now a sidecar with a gateway credential (`cnxg_...`)
  answers nothing but `/healthz` until `OPENSHELL_SIDECAR_TOKEN` is set;
  `up` writes a random one beside the credential (`0600`), and `status`,
  `doctor` and `up` present it. A gateway connected by 0.6.40 or earlier
  gets one by running `artzain connect openshell up` again (no new enroll
  token), which restarts the sidecar; until then `doctor` says so. A
  sidecar with an account key keeps its routes as they were.
- **The sidecar's heartbeat says whether `gateway.toml` still registers
  it.** The registration digest it sent was the one `up` wrote into its
  settings, so a gateway whose registration was taken out or changed still
  looked bound. A sidecar `up` installs now knows where `gateway.toml` is
  (`OPENSHELL_GATEWAY_TOML`), and each heartbeat sends `registration_found`:
  the digest of the registration in the block `up` added, `missing` or
  `unreadable`. The engine opens an `openshell_registration_changed`
  finding when it is not the installed one. Running `up` again on a gateway
  connected by 0.6.40 or earlier adds the setting.
- **`openshell-gateway --version` runs without the gateway's credential in
  its environment.** The sidecar asks it for the heartbeat; it needs
  neither the credential nor the token.
- **`artzain connect openshell up` refuses a plain `http://` engine on
  another host.** The enroll token goes to `--engine`, and the sidecar sends
  the gateway's credential to the configuration's `decision_url`: both
  must be `https://`, or `http://` to this host (`localhost` or a loopback
  address).

- **The connect script installs from hash-locked wheels.** It installed
  `artzain[openshell]` as a uv tool, which checks no hash, so every
  dependency resolved to its newest release at install time. It now makes
  an environment of its own (`~/.local/share/artzain/openshell/venv-<version>`,
  Python 3.12 as uv manages it) and installs into it only the wheels it
  names by SHA-256: the dependencies the sidecar image is built from (the
  SDK carries that lock as `artzain/openshell/sidecar-requirements.lock`),
  then the artzain wheel as PyPI serves it. `python bootstrap.py` now takes
  that wheel's SHA-256 beside the version, and renders 0.6.41 or later.

### Changed

- The README's connect command chains its lines with `&&`, as the
  dashboard's does, so a failed download or SHA-256 check stops it.
- **`artzain connect openshell up` moves a running sidecar to the
  environment it runs from.** When its unit names another Python (the uv
  tool an earlier script installed), the unit is rewritten and the sidecar
  restarts once, together with any settings `up` added. After a good `up`
  the connect script points `~/.local/bin/artzain` at its environment and
  removes the earlier uv tool and environments.

## 0.6.40

### Fixed

- **`artzain connect openshell up` reports the whole inventory after the
  gateway restarts.** The sidecar lists sandboxes as it starts, and `up`
  restarts the gateway just after that so the gateway picks up the
  interceptor. A listing that landed during the restart was sent as
  partial, and the next listing waited five minutes, so `up` said the
  engine did not have every sandbox. A failed listing is now tried again
  every two seconds for about half a minute, and `up` waits for that whole
  inventory before it reports. A gateway that stays unlistable is still
  reported as partial, with the same message.

## 0.6.39

### Changed

- **The command line, the bundle verifier and the GUI handler are built
  from smaller functions.** `artzain`'s parser is assembled one command
  group at a time, the offline audit verifier runs its steps as named
  helpers in the same order, and the GUI's proxy and refusal moved out of
  the request handler. Commands, options, help text, verdicts and every
  report and response are unchanged; tests pin them as they were.

## 0.6.38

### Fixed

- **`artzain local` limits each browser by its own address.** The engine's
  per-address limits (sign-in, sign-up, the enquiry form and the others)
  now read `X-Forwarded-For` only as far as the operator says proxies wrote
  it (`COGNEXUS_TRUSTED_PROXY_HOPS`), and ignore it by default. The local
  stack's compose file sets it to `1`, since the dashboard's nginx is the
  only way in to the engine; a proxy you put in front of the dashboard is
  one more, set in the workspace `.env`.
- **A reviewed OpenShell write goes through once it is approved.** When
  ArtzAIn answered `review` for a gateway write, the write was refused, and
  running it again after the review was approved opened another review. The
  sidecar now remembers the review for that exact write (action, target and
  payload) for a day, and cites it (`context.cites_review`) when the same
  write runs again: an approved review releases it once, a pending or denied
  one refuses it with a reason that names the review. A restart forgets the
  reviews.
- **An empty or malformed kill-switch setting no longer breaks `import
  artzain`.** `COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD` and
  `COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS` set to an empty value (as
  compose and Kubernetes pass an unset variable) or to something that is not
  a whole number raised at import. They now fall back to their defaults (5
  and 60), with a warning when the value is not a number, and a value below 1
  counts as 1.

- **`artzain login` keeps polling through a network error.** A poll that timed
  out or lost its connection (the server may still be setting up the account)
  ended the login with a traceback; it is now tried again, and a key the server
  issued while the answer was lost is replaced by a new one on the next poll. A
  certificate that does not verify ends the login at once, naming the error's
  type, rather than after ten minutes. A login that fails says why when the
  server gave a reason, and to run `artzain login` again.

- **`artzain local up` publishes the dashboard on this machine only.** Its
  port was bound on every interface, and the dashboard's nginx proxies the
  engine's API, so the engine, sign-in and `/welcome` were reachable from the
  local network. It now binds to `127.0.0.1`; set `COGNEXUS_UI_BIND=0.0.0.0`
  in the workspace's `.env` to publish it. The CLI's own requests to the
  engine name `127.0.0.1` too.

### Changed

- **What `artzain connect openshell up` writes is checked for every option.**
  `artzain.openshell.templates` renders the gateway's files for each
  timeout a configuration can carry, each telemetry choice and each
  `gateway.toml` an operator may start from. It checks the deployment
  invariants on each: the sidecar on a Unix socket and HTTP on loopback, the
  deciding registration failing closed, the credential only in the sidecar's
  private settings, and the block taken out byte for byte. The tests hold
  each rendering to a golden file, and the conformance run puts each
  `gateway.toml` through OpenShell's own `config preflight`.
- **The sidecar's heartbeat reports the gateway's own OpenShell version.**
  It asks `openshell-gateway --version` when the gateway's binary is on the
  sidecar's host (the deb or rpm gateway `artzain connect openshell` binds),
  at most every ten minutes, and falls back to the installed OpenShell SDK's
  version. It reported only the SDK's before, which the `[openshell]` extra
  does not install, so a connected gateway reported none. ArtzAIn tells a
  gateway's owner about OpenShell's security advisories by this version.

- **A PII scan whose secrets check fails says so at WARNING.** The scan
  still answers without the secrets count, and that line was at DEBUG,
  invisible at the default log level.

- **The PyPI page describes the OpenShell sidecar.** A new *OpenShell* section: the `[openshell]` extra, the one-command connect script each release carries, `artzain connect openshell` and the signed sidecar image.

## 0.6.37

### Changed

- **`artzain connect openshell doctor`.** Checks what binds the gateway on
  this host and says what is wrong: both services, the credential file
  (owner-only), the interceptor socket (a socket, owner-only, in an
  owner-only folder), the drop-in, the registration in `gateway.toml`
  against the one the sidecar was installed for, the OpenShell release
  against the approved one, the CLI, the engine reached through the
  sidecar's own proxy and CA bundle, this host's clock against the
  engine's, and whether the engine took the sidecar's reports. Each check
  is `ok`, `warn` or `FAIL`; `--json` prints them, and it exits 1 when one
  fails. It changes nothing and prints no credential.
- **`artzain connect openshell rotate-key`.** Swaps the gateway's credential
  for a new one: the live key retires any leftover key and mints the next,
  the sidecar (and with it the gateway) restarts on the new one, and once
  the engine has taken a heartbeat with it the old one is revoked. If the
  engine does not take it, the sidecar goes back to the old credential and
  the new one is revoked. Needs an engine with the key-rotation routes.
- **The OpenShell connect script.** Each release on GitHub now carries
  `connect-<version>.sh` and its SHA-256: one command, run as the
  gateway's user, that downloads uv 0.8.15 (run only if its SHA-256 is the
  one written into the script), installs `artzain[openshell]==<version>`
  as a uv tool on a Python uv manages, and runs `artzain connect openshell
  up` with its own arguments. `python -m artzain.openshell.bootstrap
  <version>` prints it.

### Fixed

- **A sidecar restart no longer races the OpenShell gateway.** The
  sidecar unit `artzain connect openshell up` writes was `Type=simple`, so
  systemd counted the sidecar started before its socket was bound, and a
  gateway ordered after it (at boot, after a sidecar crash, or restarted
  with it because it requires it) could start, find no interceptor, and
  exit. The unit is now `Type=notify`: the sidecar sends `READY=1` once
  its socket and port are bound. `rotate-key` brings a unit written by
  0.6.36 up to date, and waits for the gateway to be up again.

## 0.6.36

### Changed

- **`artzain connect openshell up|remove|status`.** Binds the OpenShell
  gateway on this host to ArtzAIn, and undoes it. This release handles the
  deb or rpm package (the gateway as a systemd user service).
  - `up` swaps an enroll token (`ARTZAIN_ENROLL_TOKEN`) for the gateway's
    credential and the approved configuration, installs the sidecar as a
    user service, adds the registration to `gateway.toml` after the
    gateway's own preflight passed, restarts the gateway, and checks that
    a write ArtzAIn denies is refused. A run that stopped is finished by
    running it again, with no new token.
  - A package install on its defaults has no `gateway.toml`: `up` writes
    one, and `remove` deletes it. The sidecar checks the gateway's signed
    calls with the key the gateway keeps beside its TLS files when
    `gateway.toml` names none. `up` checks that the `openshell` CLI reaches
    the gateway before it spends the token.
  - `remove` puts `gateway.toml` and `gateway.env` back byte for byte,
    removes the sidecar and revokes the credential.
  - The sidecar it installs lists the gateway's sandboxes, every workspace,
    through the operator's `openshell` CLI, so its inventory is whole and
    holds the sandboxes made before the connect. `up` ends by saying whether
    the engine took the first heartbeat and inventory; `status` shows it
    too. The sidecar is asked on loopback without the environment's proxy,
    which a host behind one would otherwise have been asked for 127.0.0.1.
  - It needs Python 3.11 or later. Nothing hands out an enroll token yet.
- **OpenShell sidecar: a whole inventory through the `openshell` CLI.**
  With `OPENSHELL_SIDECAR_LIST_CLI` set, each inventory lists every
  workspace (`openshell sandbox list --all-workspaces -o json`, page by
  page) and replaces what the sidecar held, so it is not partial. The CLI
  is not given the credential. `GET /artzain/reports` says whether the
  engine took the last heartbeat and the last inventory.
- **OpenShell sidecar: `Describe` and the registration come from one list
  of bindings** (`artzain.openshell.registration`), so they cannot
  disagree.
- **OpenShell sidecar: its own connection to the engine, kept warm.** The
  sidecar called the engine through the SDK's general HTTP client, which
  opens a connection for every call. Each governed write paid for the TCP
  and TLS handshakes inside the gateway's interceptor timeout.
  - Connections are now kept between calls. One is opened before the
    first request and renewed every 30 s.
  - Every call goes to the origin of `ARTZAIN_DECISION_URL` and to no
    other. No redirect is followed, as before.
  - **The environment's proxy is no longer used unless you say so.** Set
    `OPENSHELL_SIDECAR_PROXY=env` to keep using `HTTPS_PROXY`, or name the
    proxy: `http://[user:password@]host[:port]`. The proxy is asked to
    `CONNECT`; only an `http://` proxy is supported.
  - `OPENSHELL_SIDECAR_CA_BUNDLE` names the certificate authorities to
    trust for the engine, for a network that inspects TLS. The
    certificate and its host name are always checked.
  - A proxy or bundle setting the sidecar cannot honour stops it from
    starting. It does not fall back to a direct connection.
  - The deadline now covers the whole answer. An answer whose body
    trickled in could be waited for past it.
- **OpenShell sidecar: a projection report the engine could not be given
  is sent again.** It used to be counted and lost, and the sandbox showed
  as drifted until its next governed write.
  - Reports now wait in a journal and are delivered in the order they
    were made, every 15 s and whenever another report is made.
  - `OPENSHELL_SIDECAR_JOURNAL` names a file to keep them in across a
    restart (`0600`). Unset, they wait in memory.
  - The journal is hash-chained; a file that does not verify is set
    aside as `<name>.damaged` and not replayed.
- **OpenShell sidecar: a write refused by the engine's rate limit says so.**
  On the hosted engine a decision past the hourly rate is answered 429. The
  sidecar turned that into `decision unavailable`, which reads as an outage.
  - The deny now reads `decision rate limit reached (600 per hour); retry
    in 42 s`: the limit when the engine names it, and the engine's
    `Retry-After` in whole seconds, between one second and a day.
  - The gateway reports it as `RESOURCE_EXHAUSTED`, not `UNAVAILABLE`.
  - Nothing was decided or sealed for the write, and the sidecar does not
    retry it. Run the command again after the wait.
- **OpenShell sidecar: a sandbox create or update gets one decision.** The
  sidecar now decides in the gateway's `modify_operation` phase and stamps
  the decision id onto the write as the annotation
  `artzain.cognexuslabs.ai/decision-id`.
  - The `validate` phase confirms that decision without asking again, and
    asks for one itself whenever it cannot. Nothing is allowed without a
    decision.
  - Bind `modify_operation` and `validate` on `UpdateConfig`, as the engine's
    example registration now does. With `validate` alone the write is still
    decided, but it carries no stamp.
  - A gateway-global `UpdateConfig` is not stamped, and is denied as before.
- **OpenShell sidecar: a decision names its sandbox by uuid.** The gateway
  names a sandbox by name and workspace in every call but the create's
  answer, so the sidecar remembers the uuid each create returned.
  - A name it cannot resolve is decided as `name:<workspace>/<name>`.
  - The memory is the process's own, so a sandbox created before a
    sidecar restart stays unresolved, unless `OPENSHELL_SIDECAR_STATE`
    names a file to keep it in (below).
- **OpenShell sidecar: every operator write the gateway can intercept is
  decided.** 0.6.35 decided eight methods and refused any other, so a
  delete, a service exposure, an SSH session and every provider write could
  not be bound. Each now gets one decision, named for what it is:
  - `openshell_sandbox_delete`, `openshell_service_change`,
    `openshell_ssh_session` and `openshell_provider_change`, beside
    `openshell_policy_change` and `openshell_provider_attach`. The rest of
    the draft family (`UndoDraftChunk`, `ClearDraftChunks`) is a policy
    change.
  - The target names the sandbox, the provider, the provider profile or the
    gateway the write is about.
  - The payload carries names and ids. A provider write sends the
    provider's name, its profile type and the profile ids, and nothing else.
  - A draft or provider-attach decision now says which chunk, which rule or
    which provider it is about.
  - Use the engine's updated example registration, which binds all of them.
    `SubmitPolicyAnalysis` stays unbound: a sandbox's own supervisor calls
    it every few seconds, and the sidecar does not serve it.
- **OpenShell sidecar: each registration is told only its own bindings.**
  With a gateway token, `Describe` answers the example's `artzain`
  registration with the pre-commit bindings and `artzain-observe` with the
  post-commit ones. The gateway used to log a warning at every start for
  each binding a registration was told about and did not configure. A
  registration under another name is still told every binding.
- **OpenShell sidecar: a refusal names its decision.** A deny or a review the
  engine sealed reaches the operator as `decision deny (<decision id>)`.
- **OpenShell sidecar: an allowed delete forgets the sandbox's name**, so a
  later sandbox under that name is not decided as the old one.
- **OpenShell sidecar: sandboxes are kept across restarts.** Set
  `OPENSHELL_SIDECAR_STATE` to a file and the sidecar keeps each sandbox's
  name, uuid and last committed policy hash there, and reads it back when
  it starts. An update to an older sandbox is then still decided by uuid,
  and its projection is still reported.
  - The file is the owner's alone (`0600`, in a `0700` folder). It holds no
    policy body and no credential.
  - A file that cannot be read or written costs the memory across
    restarts and nothing else.
- **OpenShell sidecar: with a gateway credential it reports to the
  engine.** When `COGNEXUS_API_KEY` is a gateway's own credential
  (`cnxg_...`), the sidecar sends a heartbeat every minute, and its
  inventory every five minutes and a few seconds after a change.
  - The heartbeat carries the sidecar's version, the p50 and p95 of
    recent decision round trips, and how many reports failed since the
    last heartbeat the engine took.
  - The inventory is the sandboxes the sidecar has seen commit, sent as
    partial, unless listing is switched on (under Fixed).
  - With an account key nothing is sent. The engine takes these reports
    from a gateway credential only.
- **OpenShell sidecar: with a gateway credential it applies the team's
  base policy.** The sidecar fetches the base policy the engine compiled
  from the team's active bundle, at start and every five minutes, and
  gives it to a new sandbox whose create carries no policy. It never
  replaces an operator's policy.
  - Until it has been told what the base policy is, such a create is
    refused (`base policy unavailable`) with no decision. A create that
    brings its own policy is decided as usual.
  - When the engine says the team has none, a create is decided as it is.
  - The sidecar takes a policy only when it matches the digest the engine
    sent with it. Set `OPENSHELL_SIDECAR_BASE_POLICY` to a file and it
    keeps the policy there for the next start; a copy that does not match
    its digest is not used.
  - A sidecar on an account key is given no base policy and decides a
    create as before.

### Fixed

- **OpenShell sidecar: a kept connection is used again on Python 3.10.**
  On 3.10, every call after the first on a connection the sidecar had kept
  (see "its own connection to the engine, kept warm", above) failed with
  `http.client.ResponseNotReady`: Python 3.10's `HTTPResponse.read1` leaves
  an answer it has read to its end open, and the connection will not take a
  new one while it is. The sidecar now closes each answer once its body is
  read. Python 3.11 and later were not affected.

- **OpenShell sidecar: a gateway-wide setting write is decided, not
  refused.** 0.6.35 refused every `UpdateConfig` with `global: true`, so
  `proposal_approval_mode` could not be set to `manual` on a bound gateway.
  A setting write is now decided as `openshell_setting_change`. A
  gateway-wide policy is still refused without a decision.

- **OpenShell sidecar: a committed policy update is reported to the
  engine.** The gateway's `post_commit` call carries only the committed
  response, with no decision id, so the sidecar had nothing to report the
  new policy hash with. It now reads the stamp back from the committed
  response and reports the pair for the sandbox's uuid.
- **OpenShell sidecar: the inventory works against the OpenShell SDK.** It
  called `SandboxClient()` with no endpoint and `list_all()` with no
  workspace, so every read failed. It now lists through
  `SandboxClient.from_active_cluster()` and `list_all(workspace=...)`, for
  the workspaces `OPENSHELL_SIDECAR_LIST_WORKSPACES` names.
  - Listing uses the operator's own CLI identity, so it is off unless
    that variable is set.
  - A sandbox's effective policy hash is the one its last committed
    update reported to the sidecar. One the sidecar has not seen is sent
    empty.
  - `GET /artzain/inventory` answers `degraded` whenever its list may not
    be every sandbox.
- **A file the SDK rewrites whole is written on Windows while another
  program has it open.** Each such file is written beside itself and
  renamed over the old one, and Windows refuses that rename while another
  program has the old file open, a virus scanner reading the file just
  written, say.
  - The OpenShell sidecar gave up the write at once, and carried on
    without it: its state file (the sandboxes' names), its report journal
    and its base-policy copy did not survive a restart.
  - `artzain local` failed when it rewrote `.env`, `compose.yaml` or
    `pins.json`.
  - A refused rename is now tried again every 2 ms for up to 5 s, as
    `artzain connect openshell` and the credentials profile already did,
    and the new file is removed when it still fails. Elsewhere a rename is
    never held up by a reader, and a refused one is not tried again.

## 0.6.35

### Added

- **`artzain openshell sidecar`: the ArtzAIn sidecar for NVIDIA OpenShell
  gateways ships in the SDK** (`artzain.openshell`). It runs beside an
  OpenShell gateway, answers the gateway's interceptor calls from the
  ArtzAIn Decision API, lists sandboxes for the catalog, and seals OpenShell
  policy events. It only ever calls out. Until now it ran from the ArtzAIn
  engine's source tree.
  - It decides as `OPENSHELL_GATEWAY_ID`, whatever a request names.
  - Engine calls finish inside `OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS`
    (default 1200 ms), so a slow engine is a deny from the sidecar rather
    than a timeout at the gateway.
  - A connection reset is retried once, only for a decision that carries a
    request id; nothing else is retried.
  - Engine calls use the SDK's HTTP client (no redirects, proxy from the
    environment), and only an `http` or `https` engine URL is accepted.
  - With `OPENSHELL_SIDECAR_GRPC` set (a `unix://` socket or a loopback
    port), it serves the gRPC `GatewayInterceptor` service the gateway calls.
    It answers the gateway's protocol handshake without contacting the
    engine, so a gateway can start while the engine is unreachable.
  - With `OPENSHELL_JWT_PUBLIC_KEY` and `OPENSHELL_JWT_GATEWAY_ID` set, every
    call must carry the gateway's signed token (`gateway_jwt`). A call
    without one is refused, which the gateway treats as a failed call: the
    write is refused, and the gateway does not start while its first call is
    refused.
  - The gRPC service needs the new `artzain[openshell]` extra (`grpcio`,
    `protobuf`, `cryptography`). The HTTP routes, including a new open
    `GET /healthz`, need nothing extra.

  Pinned to OpenShell v0.1.2.

### Fixed

- **A Go pseudo-version's timestamp is not read as a card number.** The card
  rule matches 13–19 digits that pass Luhn, with no issuer prefix. A module
  pseudo-version (`vX.0.0-yyyymmddhhmmss-<12 hex>`, and the forms that put
  `.0.` before the timestamp) carries a 14-digit timestamp, and about one in
  ten passes. On the `vX.0.0-` form the hyphen is a separator the rule
  allows, so the match was the patch `0` glued to those 14 digits.
  `scan_text` and `redact_text` leave that timestamp in place. A card number
  still counts, with or without separators and inside a sentence, including
  one written beside a pseudo-version.
- **`artzain quickstart` and `decide()` report a failed request without its
  error's text.** `artzain quickstart` printed why the API key could not be
  verified, and `decide()` raised why the Decision API could not be reached,
  as the text of the error the request raised. That text can quote what a
  terminal or a log must not: `http.client` quotes a header value it will not
  send, so an API key it refused was printed in full, right under the line
  that shows only its prefix, and a certificate issued for another name puts
  the host in it. The `error` of `fetch_api_key_identity()` and the message of
  a `DecisionError` now give the error's type (for a `URLError`, the type of
  the error it wraps) and where the base URL came from, or say that no request
  can be made with the base URL and the API key that are set; the text is
  logged at DEBUG, unmasked, under `artzain.cloud` and `artzain.decide`. The
  `DecisionError` for a request that was sent, or that `http.client` refused,
  has neither a cause nor a context: a caller's `logger.exception` rendered
  the error it stood for, text included. A 200 answer that is not JSON is
  `unexpected_response` from `fetch_api_key_identity()`, and from `decide()`
  a `DecisionError` that says so rather than "unreachable".
- **No CLI command prints an error page.** A command whose request was
  answered with a page rather than the API's JSON printed the page: `audit
  export`, `registry export`, the licence commands and the commands that read
  the API's JSON. A page can name the host, or echo the request headers back,
  the API key or the session token among them. The command now prints the
  status and that a page came back, and logs the page at DEBUG under
  `artzain.cli`. A CDN/WAF block page is named as one, now also a 403 page
  that names Cloudflare or gives its error code 1010, and `artzain login` and
  the sign-in `artzain quickstart` offers follow it with their hint.
  `licence attest`, `licence anchor-request` and `licence anchors` printed the
  text of an error their request raised; they print its type, and log the text
  at DEBUG, and an answer that holds nothing ends them with a message, where
  they could stop on a traceback, or `licence anchors` write an export of
  nothing.
  A base URL, an API key or a session token no request can be made with ends
  a command with a message that names the settings, where a traceback or
  those three commands' message quoted the value, and a 200 answer that is not
  JSON ends it with a message rather than a traceback. When an export's error
  answer has a `detail`, the export prints it, as the other commands do,
  rather than the whole answer.

## 0.6.34

### Fixed

- **The Python scaffolds' no-key note follows the SDK's own credential
  resolver, and offline replies no longer say "sealed" or "queued".** The
  note `artzain init` writes for CrewAI, LangGraph and MCP checked only
  `COGNEXUS_API_KEY`, so after `artzain login` (or with `MYAPP_API_KEY`) it
  still claimed calls ran against the local guard library and were not
  sealed, while `decide()` went online. It now asks `artzain.has_api_key()`,
  which uses the same resolver `decide()` does, and prints only whether a
  key is configured — never anything derived from the credentials profile.
  When a decision carries `offline=True`, an allowed call says "decided
  offline, not sealed" instead of "sealed as …", and a review says it is
  offline and not queued instead of "QUEUED FOR REVIEW" (nothing is queued
  offline, and nothing would run the call). The MCP note stays on stderr.

## 0.6.33

### Fixed

- **Screening a payload stays bounded when the text holds a long run of combining marks.** The check that folds compatibility forms normalised the whole text in one step, and that step can take time that grows with the square of such a run, long enough for one request to hold a worker. A run past the usual limit is broken before that fold, so the time grows with the length of the text. A keyword written in a compatibility form, or split by an invisible character, is still caught when a long run sits beside it. Ordinary text is read as before.
- **`configure()` changes the API key and the base URL together.** A call
  that read them while `configure(api_key=..., base_url=...)` was changing
  them could take the new key with the previous base URL, or the previous key
  with the new one, and send the key to a host it was not configured for.
  While the credentials profile could not be read, the policy-rules loader
  could pair them the same way and serve rules fetched with another key. Only
  an application that calls `configure()` and sends at the same time, on two
  threads or with one of the two in a signal handler, could see this. The
  two are now kept as one value that `configure()` replaces in one step and a
  call reads in one step, so a call gets them as one `configure()` left them,
  never a mix of two. A `configure()` that raises, for a value that cannot be
  turned into text, now changes neither; it could leave the new key with the
  previous base URL.
- **`artzain gui` hands the session it opens with the API key only to the
  page it opened.** The local server handed that session to any request that
  reached its port. It now answers only requests addressed to `127.0.0.1` or
  `localhost`, refuses requests another site sends, grants no other origin
  access to its responses, and opens the session only for a tab opened from
  the address it opens and prints, which carries a code for this run after
  `#`. Opened without that code, the page asks for that address or a
  password sign-in. With `--no-browser`, open the printed address.
- **An API key no longer follows a redirect to another host.** `urllib`
  copies a request's headers onto the request it makes to the host a
  redirect names, so an answer that was a redirect sent the key there: from
  `decide()`, the policy-rules fetch, the key check behind `artzain
  quickstart`, the CLI's commands and `artzain gui`'s key exchange. The
  `artzain gui` proxy passed on the browser's session token the same way.
  The API answers none of these requests with a redirect, and they now follow
  none: `decide()` raises `DecisionError` with its status, the CLI commands
  that send the key report it as a refusal, and the proxy relays its status
  to the browser without its `Location`. The event and policy-decision posts
  never followed one; they now log one as a failed send, as they do any other
  status that is not a success. These requests go through the SDK's own
  opener, so one an application installs with
  `urllib.request.install_opener()` no longer applies to them, nor does a
  test double patched over `urllib.request.urlopen`. Their proxies are still
  the ones urllib would use
  (the environment's, or the system's on Windows and macOS), for `http` and
  `https` only: a proxy set for another scheme was sent a request for it,
  key included, over plain HTTP.
- **A base URL must be an `http://` or `https://` URL that names a host.** The
  event and policy-decision posts went over plain HTTP for any scheme other
  than `https`, so a mistyped scheme sent them, API key included,
  unencrypted, and a base URL without a scheme was dialled with no host at
  all. A key is now sent to no other base URL, nor to one with white space,
  a control character, a user or a password in it, in its host
  percent-encoded or not: nothing is sent, and the error or log line names
  the setting that holds the URL (`configure(base_url=...)`,
  `COGNEXUS_API_BASE_URL`, the credentials profile or a project `.env`),
  never the URL. As for a key and a host that do not belong together,
  commands that read the key stop with that message, `artzain gui`, `init`
  and `local activate` among them, and `has_api_key()` is false. The licence
  commands refuse a deployment URL (`--base-url`, `COGNEXUS_LOCAL_URL`) of
  any other form too, naming the setting. `http://` is still accepted, for
  any host: a deployment on this machine, such as the one `artzain local`
  runs, uses it, and over it the key travels unencrypted, as before.
- **The MCP scaffold runs on the MCP SDK 2.x.** The file
  `artzain init --framework mcp` writes registered its handlers with the 1.x
  server's `list_tools()` and `call_tool()` decorators, which MCP SDK 2.0
  removed, so 0.6.32 pinned its install line to `mcp<2`, while
  `pip install mcp` installs 2.x. It now uses the 2.x low-level server, which
  takes the handlers in its constructor (`on_list_tools=`, `on_call_tool=`):
  `call_tool` stays the one handler every tool call reaches, so the gate still
  covers every tool. The install line reads `pip install artzain "mcp>=2,<3"`,
  and on the 1.x SDK the file exits saying what to install. A call it did not
  run (`review`, `deny`, or an outcome it does not recognise) now comes back as
  a failed tool call (`isError`), so a client does not take the refusal for
  the tool's output, and a call that sends no arguments is gated with `{}`. A
  call to a tool the server does not list is refused as a failed call without
  a decision; it was decided on and answered as the tool's output. A call that
  raises comes back as a failed call, with the traceback on stderr; otherwise,
  over the 2025 protocol, the 2.x server answers with an error that carries
  the exception's text, which can quote a password or a key. A file generated
  by an earlier version still needs `mcp<2`; to run it on 2.x, regenerate it
  with `artzain init --framework mcp --force`, which overwrites the file.
- **Files the SDK writes are its user's alone from the moment they exist.**
  `artzain local` wrote the stack's `.env` and `artzain policy keygen` the
  signing key readable by other users until a later `chmod`, and the
  pre-upgrade database dumps were never restricted, in a workspace folder any
  user could list. They are now created new, `0600`, never written into a
  file that was there before, and the workspace, its `backups` folder and a
  new key folder are `0700`, whatever the umask. A workspace folder
  (`COGNEXUS_LOCAL_HOME`) that is another user's is refused.
- **Prompt-defence events no longer default to a shared `/tmp`.** With neither
  `COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR` nor `REPORTS_DIR` set, the events and
  their tamper-evident chain went to `/tmp` (`\tmp` on the current drive on
  Windows), where other users could read the previews and change the chain.
  They now go to a folder only you can read: `~/.artzain/events`, or
  `%LOCALAPPDATA%\artzain\events` on Windows; on a host with no writable
  home, or where that folder is another user's, `artzain-events-<uid>` in the
  temp folder, refused unless it is a folder of your own. Events already in
  `/tmp` stay there, readable by other users: move or delete
  `prompt_defense_events.jsonl` and `prompt_defense_events.chain_state`
  there, or set `COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR` to a folder of your own
  and move them to it.
- **An event or a human decision is posted to the dashboard once.** The posts
  share one kept-alive connection, and any failure on it was retried on a
  fresh one, so an answer that was slow, cut short or never came, after the
  server had read the request, stored the event, or an approve/deny verdict,
  twice. A post is now sent again only when sending it failed. A kept
  connection is replaced before a post goes out on it when the server's close
  has reached it, or when it has been idle for a minute, in case a NAT or a
  firewall on the way has dropped it. A post whose answer never arrives, or
  that meets a connection closed on its way, is logged as failed rather than
  sent again.

## 0.6.32

### Fixed

- **The CrewAI and MCP scaffolds run a tool only when the decision is
  `allow`.** The guards that `artzain init --framework crewai` and
  `--framework mcp` write refused `deny` and queued `review`, but ran the tool
  on any other outcome, so a decision whose outcome was null, empty or not one
  they recognised ran the tool. They now run it only on `allow`, queue
  `review`, and refuse anything else; an outcome they do not recognise is
  named in the refusal. The LangGraph scaffold's graph had no edge for such an
  outcome, so the run raised, and it followed an outcome sent as a list to its
  action node; it now routes every outcome but `allow` and `review` to
  `refused`. The MCP scaffold also called the blocking `decide()` on the
  server's event loop, which held every other request until the decision came
  back; it now runs the gate in a worker thread (`asyncio.to_thread`). Files
  generated by an earlier version keep the old check: make it run the tool
  only on `allow`, or regenerate with `artzain init --framework <name>
  --force`, which overwrites the file.
- **The MCP scaffold names the MCP SDK it needs, and keeps stdout for the
  protocol.** It uses the 1.x server's `list_tools()` and `call_tool()`
  decorators. MCP SDK 2.x registers handlers in the `Server` constructor
  instead, so on 2.x the file failed at import. Its install line now reads
  `pip install artzain "mcp<2"`, and on 2.x it exits saying so. Its note that
  no API key is set now goes to stderr: on stdout, the JSON-RPC channel of a
  stdio server, it was a protocol error for the client.
- **The LangGraph scaffold's second run screens the draft it shows.** Its
  `plan` node replaced the draft it was given with its own, so the run meant
  to show the guard stopping an injected draft screened the benign one and
  acted. `plan` now keeps an action, target and draft it is given.

### Changed

- **`artzain init --framework openshell` writes an OpenShell policy scaffold.**
  The file is `artzain_openshell_policy.yaml`: a network policy that allows the
  Decision API and a local inference host, with enforcement on, and a skill that
  proposes a narrow `policy.local` rule and waits. The command does not tell you
  to run the YAML as Python. `artzain registry list` and `artzain registry export`
  accept `--source openshell`.

## 0.6.31

### Fixed

- **An offline decision's reasons name the finding that decided it.** The
  offline policy vote seals at most eight findings, and
  `PolicyEnforcementEvaluator.evaluate` appends the conduct findings after every
  rule finding, so eight matching rules pushed a critical conduct finding past
  the cap. `decide()` heads each reason with the vote's first finding, so the
  decision read `critical` while its `reasons` named a low rule: the verdict was
  right, the reason named the wrong rule. The vote now seals its most severe
  findings, ties in the order they were evaluated, and an unpaired-surrogate
  finding still comes first. Until this release offline `decide()` screened
  only the built-in conduct rules, which carry no patterns of their own, so no
  offline decision reached the cap; it now screens your own rules as well (see
  Changed), which can. The order is the one the platform's decision engine
  seals, so a vote means the same thing on either side. The order changes no
  verdict or severity; a vote listing findings of several severities now lists
  them by severity rather than by rule order.
- **A tool call whose arguments are a document is no longer refused for its
  shape.** The structural ceilings on a `kind="tool_call"` payload read every
  nesting level's keys as one total, and allowed eight levels of nesting, so
  ordinary calls were reviewed as smuggled payloads: a deployment manifest or a
  search query DSL for nesting, an itemised invoice or a spreadsheet append for
  its rows' keys. Nesting is now allowed to 32 levels, and the key ceiling
  counts the keys of one object, where thousands of keys is a dictionary handed
  over as an argument list rather than an argument list. A call's total size is
  bounded as before by the payload caps and by the coverage ceiling of the
  screens that read it, which reports a call carrying more strings than are
  screened one at a time. Nesting deep enough to exhaust a parser still fails
  closed.

- **`rules_checked` counts each rule screened once.** `screen_client_policy()`
  merges the built-in conduct rules into the rules it screens, and
  `PolicyEnforcementEvaluator.evaluate` then added their number a second time,
  so the report for any non-empty text counted two rules more than it was
  screened against, and two more than the audit row written for the same
  screening. It is now the length of the rule list screened, whatever the text.
  Audit rows written by `screen_client_policy()` already recorded that number
  and are unchanged. For a non-empty text, a report's `rules_checked`, the
  `client_policy` log lines, and a row you record yourself with
  `record_policy_enforcement_event()` without `rules_checked=` read two lower
  from this version. A non-empty list you hand the evaluator without the
  conduct rules is counted as it is, and the conduct detector still runs beside
  it; an empty list screens nothing, conduct included (`screen_client_policy()`
  always merges the conduct rules in).
- **The local audit preview is redacted, as the module always said it was.**
  `events` promised "No raw user text is stored", but the preview it wrote to
  `prompt_defense_events.jsonl` was only whitespace-collapsed and cut to 96
  characters, so shorter prompts were stored as written and were sent to the
  dashboard that way. The preview now masks the checksum-validated identifiers
  (SSN, card, IBAN, UK NINO) and `key=value` secrets before the cut, the same
  as the engine's own audit writers. The module and package docstrings and the
  README now also state the limit: text holding none of those is still stored
  as written, so the events directory stays as sensitive as the prompts it
  describes.
- **A prompt sent with a generation outcome is redacted too.** The preview
  helper in `cloud` was a second copy that did not redact, so a prompt passed
  to `post_generation_outcome()` (whose `prompt` argument documents that "Only
  a redacted preview is sent"), or noted for the session and attached to later
  events, travelled unmasked. Both paths now share the one implementation.
- **A failed dashboard call is logged without what came back.** A failed call
  to the dashboard (posting an event or a policy decision, fetching the policy
  rules) was logged at WARNING with the start of the API's answer, or with the
  text of the error the call raised. Either can name the host, as a proxy's
  error page or a certificate issued for another name does, or hold the API
  key: an error page that echoes the request headers does, and so does the
  error `http.client` raises for a header value it will not send, which quotes
  the value. The WARNING line now gives the call, the HTTP status or the
  error's type, and where the base URL came from (`configure(base_url=...)`,
  `COGNEXUS_API_BASE_URL`, the credentials profile or the default). The answer
  and the error's text are logged at DEBUG, unmasked: keep the `artzain.cloud`
  logger above DEBUG wherever its records leave the machine. The hints for an
  invalid or revoked key (401) and for a CDN or WAF block (403) are unchanged.
- **`verify_chain()` documents what it actually checks.** The module and
  function docstrings said that without `COGNEXUS_AUDIT_HMAC_KEY` "only
  hash-chain integrity (prev_hash / entry_hash) can be verified". There is no
  such partial pass: every chained entry's signature is checked, so a log
  written with the per-process key fails in any later process with `HMAC
  mismatch at seq=1`. The docstrings now say so, and that the key is read once
  per process, so setting it after the first signature has no effect.
- **A reply with a Markdown code block is no longer a `review`.** Offline
  `decide(kind="model_output")` screens a reply with the strict injection
  preset, where a line of only `---`, `###` or a code fence was a `medium`
  delimiter finding: the fence closing any code block, a horizontal rule or a
  line of hashes sent an ordinary reply to review. In a reply that is not
  JSON such a line now reads as a line break between the text around it. It
  is still a delimiter finding when the next line that holds anything opens
  with a chat role's label (`SYSTEM:`, `**User:**`), a turn written into the
  reply. The platform reads a reply the same way. A reply that is JSON, and
  the other payload kinds, read these lines as before.
- **A key configured after the first rules load fetches your team's rules.**
  With no rules configured and no API key, `load_client_policy_rules()` cached
  the conduct rules it returned for the rest of the process, so a key
  configured afterwards (`configure()`, `artzain login`) never fetched the
  team's rules for `screen_client_policy()`. With nothing to load, nothing is
  cached now.
- **An offline destructive-action reason names the most severe match.** A
  screen lists its matches in the order the guard walks its rules, which is by
  kind rather than by severity, and the offline destructive-action vote kept
  that order for a plain-text payload. `decide()` heads each reason with the
  vote's first finding, so a reply holding an `UPDATE` without `WHERE` (high)
  and a `git push --force` (critical) was denied as critical with a reason
  naming the `UPDATE`, and a critical match walked after eight high ones fell
  past the eight findings a vote keeps. The vote now reads its screen through
  `combine_screens()`, as the platform's decision engine does and as the vote
  already did for a tool call or a JSON reply: most severe first, and matches
  of one severity in the order they were found. A guard that fails internally
  is named `guard.error` in the findings and the reason, as on the platform;
  offline, the reason read only `critical`. Verdicts and severities are
  unchanged.
- **A failed policy-rules fetch no longer passes for a tenant without rules.**
  `load_client_policy_rules()` caches the rules it loads for the process. A
  fetch from `GET /api/policy-enforcement/rules` that failed (an HTTP error,
  among them the 503 the platform answers while it cannot read your rules, a
  timeout, an answer that was not a rule list, or an API key that may not be
  sent to the host that is set) came back as an empty list and was cached as
  one. The process then screened on the built-in conduct rules alone until it
  restarted, and a failed `force_refresh=True` swapped your rules for them the
  same way. A failed fetch is now never cached. A later call makes it again
  once a short backoff has passed (doubling up to a minute, and kept by
  `force_refresh=True` too, so a loop does not hammer the API); the call that
  makes it waits for it, as a first load does, and other callers are served
  meanwhile. Until a fetch succeeds, the rules fetched last are still served,
  for up to five minutes from the first failure
  (`COGNEXUS_BUNDLE_LAST_GOOD_GRACE_SECONDS`, the platform's own bound on a
  last-known-good copy), and only for the API key and host they were fetched
  with; otherwise the conduct rules alone apply. A warning says which when a run
  of failures starts, when what it serves changes, and the first time each kind
  of failure occurs in the run; the retries in between are logged at DEBUG. An
  answer with no rules is still an answer, and is cached.
- **A key or base URL changed with `configure()` now reloads the policy
  rules.** After `configure()` changed the API key or base URL,
  `load_client_policy_rules()` kept serving the rules it had fetched for the
  previous ones until `force_refresh=True`. The next call now loads them again
  when the key and host in use differ from those the cached rules were fetched
  with; a `configure()` that leaves them as they were fetches nothing. A
  process that switches keys with `configure()` for each tenant therefore
  fetches on each switch: pass `rules=` to screen for several tenants from one
  process. A key or host changed in the environment or the credentials profile,
  rather than with `configure()`, is not noticed until the rules are next
  fetched, by `force_refresh=True` or by a retry after a failed fetch.
  `load_client_policy_rules()` also makes the request
  itself rather than through `fetch_client_policy_rules()`, so replacing that
  function no longer feeds the loader: set `COGNEXUS_POLICY_RULES_JSON` or pass
  `rules=` instead. `fetch_client_policy_rules()` keeps its signature and still
  returns `[]` for a failed request, now also for a base URL it cannot make a
  request from, where it raised `ValueError`.
- **A credentials profile that cannot be read is no longer a profile without a
  key.** `read_profile()` answered `{}` for a profile that is not there and for
  one that is there but cannot be read (another program holds a lock on it,
  its permissions shut you out, it is not UTF-8 text), so the API key it holds
  was taken to be unset: `load_client_policy_rules()` put the built-in conduct
  rules alone in place of your team's rules, events were skipped without a
  warning, and `decide()` decided offline. `resolve_credentials()` now raises
  `CredentialConflictError` for such a profile, naming no value, and while it
  cannot be read no API key is sent, whichever setting holds it, unless a
  project `.env` sets both the key and its host. Events are held back with a
  warning, `decide()` raises `DecisionError`, a CLI command stops and says why,
  and the rules loader counts it as a failed fetch: its backoff applies, and
  the rules fetched last are still served within the same window, unless a key
  or host set with `configure()` or in the environment is not the one they were
  fetched with. `read_profile()`, `profile_api_key()` and `profile_base_url()`
  still answer `{}` and `None` for it. A profile that is not UTF-8 text made
  them, and event posting, raise `UnicodeDecodeError`; it now reads as one
  that cannot be read. What is at the path and is not a file (a directory, a
  device, a pipe) is still no profile, and is not opened, and so is a profile
  in another user's directory that you may not search, such as root's home in
  a container.
- **The key and host in use come from one reading of the profile.**
  `resolve_credentials()` reads the profile once, and `decide()` and each CLI
  command resolve their credentials once per call.
- **`write_profile()` replaces the profile whole.** It truncated the file and
  wrote it again, so a process reading the profile while `artzain login` ran
  could find it empty or half written, and read no key; on Windows, a profile
  another program held a lock on was left empty. The new profile is now
  written to a file beside it, which on POSIX only its owner can read from its
  creation rather than once written, flushed to disk and moved over the old
  one. A symlink is written through, as before, when you, root or the user
  `sudo` or `doas` runs for made it. A profile that is another user's is not
  replaced: the write is refused, as writing it in place was when their file
  could not be opened, but for root under `sudo` or `doas` with HOME kept
  writing for that user, who is given the new profile, as they are one made
  in a directory of theirs. No one else is handed a new key. A device at the
  profile's path (the null device, to keep no key) is written to as before
  rather than replaced, and a pipe that nothing reads is refused rather than
  waited on. On Windows, where a file another program has
  open cannot be replaced, the move is tried again for a few seconds, and then
  `artzain login` says the profile could not be saved, leaving the old one as
  it was. A new file an interrupted write left beside the profile is removed
  by a later write, once it is old.

### Changed

- **The profile's directory is closed to other users only when it is the
  SDK's own.** `write_profile()` set the directory the profile is in to mode
  0700 whichever it was. It now does so for `~/.artzain` and for a directory
  the write makes; one that `COGNEXUS_CREDENTIALS_PATH` names and that is
  there already keeps its mode, and the profile in it is still its owner's
  alone.
- **Audit records no longer carry the `user_prompt` copy of the preview.**
  Every record stored the same preview twice, under `preview` and
  `user_prompt`; the engine's writers dropped that duplicate and the dashboard
  reads `preview`. Rows written by this version, the records handed to
  `on_event` and the events posted from it carry `preview` only, so read
  `preview` wherever you read `user_prompt`. An `on_event` callback that
  raises is only logged at DEBUG, so a sink that looks up `user_prompt` would
  stop storing rows without a warning.
- **Offline `decide()` screens your own policy rules.** With no API key,
  `screen_client_policy()` screens the rules `load_client_policy_rules()`
  returns, from `COGNEXUS_POLICY_RULES_JSON` or else the JSON file
  `COGNEXUS_POLICY_RULES_PATH` names, beside the built-in conduct rules.
  `decide()`'s offline policy vote screened the conduct rules alone, so text
  that broke one of your rules was refused by the one and allowed by the other.
  The vote now screens the same list, and never fetches your team's rules, so
  an offline decision still makes no network call. A list that loads is kept
  for the process (`load_client_policy_rules(force_refresh=True)` reloads it).
  Offline, text matching a `high` or `critical` rule of yours is now `deny`
  where it was `allow`; a `low` or `medium` match is listed on the policy vote
  and leaves the outcome as it was. Rules that cannot be loaded (a missing file,
  JSON that does not parse or is neither a list nor `{"rules": [...]}`) make the
  vote `deny`, carrying the error, where `screen_client_policy()` raises.
  Online, the platform decides against your team's rules, and the local ones
  are not sent.


- **A policy bundle can move the two tool-call ceilings per tool.**
  `max_arg_depth` and `max_arg_keys` beside a tool's `required_args` in
  `guard_config.tool_contracts` set that tool's ceilings; under `"*"` they set
  the bundle's, and a tool's own value wins. Either direction: a tool handed a
  manifest gets more room, and a bundle whose tools all take flat arguments can
  pin them tighter than the defaults. A value that is not a whole number above
  zero leaves the default in force, and neither can be set above depth 64 or
  2000 keys, so the ceilings are adjustable and not removable. A ceiling
  finding now names the value that applied.

## 0.6.30

### Fixed

- **A policy rule's own pattern can no longer hold up a decision.** A rule
  carries `violation_patterns`, and a pattern is matched by trying the ways the
  text can be divided between its parts. A few shapes multiply those ways
  rather than adding them, so what one costs grows faster than the text it
  screens: a single ordinary payload could occupy the screening far longer than
  a decision may take. Screening now runs under a wall-clock budget
  (`PolicyEnforcementConfig.screening_budget_seconds`, shared across every way
  one payload is read) and raises `PatternBudgetExceeded` rather than reporting
  that it found nothing, so the caller decides the outcome by its own failure
  model. Two budgets, because a rule set is normally many cheap patterns:
  ``pattern_budget_seconds`` bounds any one search, which is what a costly
  pattern runs into, and ``screening_budget_seconds`` is a far looser ceiling on
  the whole call, so a tenant is never refused merely for having a lot of rules.
  Those shapes are also refused outright when a rule's patterns are
  compiled, with `PatternTooCostly` naming the shape: a bundle carrying one is
  rejected as it is loaded rather than on every decision afterwards.
  `pattern_refusal()` answers the same question on its own, for a tool checking
  a bundle before it is uploaded.
- **Rules read out of a policy document stay proportionate.** A sentence's
  wording was turned into a pattern chaining up to six of its words, whose gaps
  multiplied in the same way; it now chains three, which names what a sentence
  forbids without the cost of screening growing faster than the payload.
- **A rule that reuses a built-in conduct rule's id no longer answers for it.**
  Where one of your rules carried the id of a built-in conduct rule (profanity
  in a client context, insults aimed at the recipient), its finding could take
  that rule's place in the report: text the conduct detector rates `high` or
  `critical` was reported at your rule's severity, and `should_block_policy()`
  did not refuse it. Those ids are now reserved in
  `PolicyEnforcementEvaluator.evaluate`. Your rule keeps its own patterns and
  severity and is reported under `<id>/tenant`, and the conduct finding stands
  beside it at its own severity. This holds for rules from every source —
  `rules=`, `COGNEXUS_POLICY_RULES_JSON`, `COGNEXUS_POLICY_RULES_PATH`, the
  platform endpoint, or a list you assemble and hand to the evaluator yourself.
  Your rules are not modified; the report and the audit row name the moved id.
- **The rule list screened against holds the built-in conduct rules themselves.**
  One of your rules carrying a built-in conduct rule's id also kept that rule out
  of the list, so `load_client_policy_rules()` handed back your copy of it
  instead — its title, summary and severity, however far they had drifted — and
  `rules_checked`, on the report and on the audit row, counted the copy. A
  same-id rule carrying no patterns of its own is now dropped for the built-in
  rule; one carrying patterns is your own rule, applies exactly as it is
  written, and is listed beside the built-in rule under the `<id>/tenant` of the
  entry above. This is the merge the platform's decision engine has always made
  for an active bundle's rules, so a rule list now means the same thing on either
  side. The list you pass to `screen_client_policy()` is not modified.

### Changed

- **`regex` is used for rule patterns when it is installed**, as the one engine
  that accepts a deadline mid-search; `pip install artzain[bounded]` asks for
  it. Without it the package behaves as before, matching with `re` and checking
  the budget between patterns, and the refusal above is then the only thing
  keeping a costly shape from being matched. Both engines are held to the same
  matches, pattern for pattern, by a test over every pattern shipped here.

## 0.6.29

### Fixed

- **Artzain Chat (local) says why the API key did not sign it in.** When the
  platform refused to open a session with the configured key (a key bound to
  an agent, for instance), `artzain gui` dropped the reply and the page said
  "No API key found". The page now shows the platform's reason in the sign-in
  form, which points to a key that is not bound to an agent or to signing in
  with your password there. The two-factor message is unchanged.

## 0.6.28

### Fixed

- **The CLI now uses the profile's base URL.** `artzain login` records the
  host it logged in against beside the key, and `artzain quickstart` writes
  `COGNEXUS_API_BASE_URL` beside the key in `.env`, but the CLI read only the
  key from either and sent it to `COGNEXUS_API_BASE_URL` or the default host.
  After logging in to a self-hosted deployment, `artzain gui`, `policy`,
  `registry`, `audit export` and `quickstart` in a later shell sent that
  deployment's API key to the public host. A key from the profile now goes to
  the profile's host, and a `.env` key to that file's host.
- **The library pairs the key and the host the same way.** `decide()` and the
  cloud calls took the key and the host independently, so the profile's key
  could go to a host named by `COGNEXUS_API_BASE_URL` or
  `configure(base_url=...)`, and an environment key to the profile's host.
  The profile's host is now used only with the profile's key; any other key
  goes to `configure(base_url=...)`, `COGNEXUS_API_BASE_URL` or the default.

### Changed

- When `COGNEXUS_API_BASE_URL` or `configure(base_url=...)` names a different
  host from the one the key was issued with, nothing is sent: the CLI exits
  with a message, `decide()` raises `DecisionError`, and event posts are
  skipped with one warning. The message names the settings, never their
  values. Fix it by setting `COGNEXUS_API_KEY` for that host, running
  `artzain login` against it, or unsetting the base URL.
- `artzain.credentials` adds `resolve_credentials()`, `ResolvedCredentials`,
  `CredentialConflictError` and `DEFAULT_BASE_URL`.

## 0.6.27

### Changed

- `artzain local` sets `COGNEXUS_MCP_TOOL_SUPPLY` to `enforce`. A tool list
  with no accepted fingerprint is denied. A fingerprint that no longer
  matches the accepted one is reviewed until a manager accepts it.

## 0.6.26

### Fixed

- The prompt-injection screen's `credential_exfil` handoff rule (a credential
  word, then give / send / paste / dump / exfil / leak, then a recipient)
  matched honest tool and API wording: "pass reveal=true to show them",
  "Passwords are stored hashed; do not send them in chat.", and "Maximum
  tokens to keep; send a larger value to keep more of them." Those came back
  `high` (`deny`), including under a closed envelope's tool-definition
  screen. The rule no longer treats `show` as a handoff verb, no longer
  treats a bare `token` / `tokens` as a credential (access, auth and bearer
  tokens still count), and skips a verb that `do not`, `don't` or `never`
  immediately precedes. A request that pastes or sends an API key, or that
  puts words between the negation and the verb, is still found.

## 0.6.25

### Fixed

- Destructive-action guard: the `sql.truncate` rule matched TRUNCATE followed
  by any word, so ordinary text that uses "truncate" as a verb, a `truncate`
  CSS class, a docstring, or a list of tags holding the word was a critical
  finding in `screen_action()` and a denied offline `decide()` for
  `model_output` and `tool_call` payloads. The rule now reads a TRUNCATE
  statement: the words that may come before its tables (such as `TABLE`,
  `ONLY` or `IF EXISTS`), one or more tables, any of TRUNCATE's own options
  (such as `CASCADE` or `RESTART IDENTITY`), and then the end of the
  statement. It reads names in plain, escaped or doubled quotes, and names
  that code builds from template placeholders or joined strings. TRUNCATE
  statements in SQL scripts, in code that builds or runs SQL, and in the
  strings of a tool call are still critical, including some forms that 0.6.24
  did not catch. The rule takes time linear in the length of the text.
- Offline `decide(kind="tool_call")` no longer reads an array that begins with
  the word "truncate", such as a package's keywords or a schema's enum, as a
  TRUNCATE statement. A statement passed as one argument of a command, or as
  the arguments after a database client, is still read.
- Destructive-action guard: the `sql.drop_table`, `sql.drop_database`,
  `sql.drop_index`, `sql.delete_no_where` and `sql.update_no_where` rules
  matched their keywords and a word, so English such as "drag and drop table
  rows to reorder them", "delete from the list any items you no longer need"
  and "we update the set of rules every week", and code or documentation that
  names the statements (`blocked_patterns=["DROP TABLE"]`), were critical or
  high findings in `screen_action()` and in offline `decide()` for
  `model_output` and `tool_call` payloads. The rules now read a statement, as
  `sql.truncate` does: DROP, what it drops (such as `TABLE` or `DATABASE`),
  one or more names, any of DROP's options (such as `CASCADE` or `PURGE`),
  and then the end of the statement; DELETE FROM, a table, an optional alias,
  and then the end of the statement or a clause such as `RETURNING` or
  `LIMIT`; UPDATE, a table, SET and an assignment. DELETE and UPDATE still
  count only without a WHERE in the same statement. The rules read names in
  quotes, including PostgreSQL's `U&"..."` and a string where SQLite takes one
  as a name, and names that code builds from template placeholders or joined
  strings. Statements in SQL scripts, in code that builds or runs SQL, and in
  the strings of a tool call are still found, including some forms that 0.6.24
  did not catch, such as `DROP TEMPORARY TABLE`. A name that is only a template
  placeholder (`DROP TABLE {table}`) or a single-quoted string is read where
  the keyword is in capitals or a terminator follows, as it is in generated
  SQL, but not where it reads as interface text (`Delete from {name}`). A DROP
  finding's excerpt now runs to the first name. The rules take time linear in
  the length of the text.
- `decode_strings` and `decoded_texts` keep reading after a JSON string a
  strict decoder rejects for a bad escape. The literal ends at the first quote
  no backslash escapes; valid escapes are decoded and an invalid one stays as
  written, and each literal is decoded from its own slice. An unterminated
  literal still yields its decoded prefix, and an incomplete escape at the end
  of the text is still dropped. Screens that use those strings therefore still
  see the strings that follow the bad escape.

### Added

- Destructive-action guard: a `find` rooted at `/`, `~` or `$HOME` that deletes
  (with `-delete`, or an `-exec`/`-execdir` that runs `rm`) is flagged
  `critical` (`fs.find_delete_root`). A `find` under any other path, or one that
  does not delete, is not flagged.

### Changed

- Destructive-action guard: the `rm` rules recognise more spellings of a
  recursive root, home or working-directory removal. A home or working-directory
  glob target (`rm -r ~/*`, `rm -r $HOME/*`, `rm -r ./*`) is now rated a
  root-class wipe, as `rm -r *` and `rm -r ~` already were; and a removal whose
  flag or target is separated from the command by shell quoting or expansion is
  read as the command it is, by screening a shell-normalised reading of the text
  alongside the text as written.

### Fixed

- Destructive-action guard, SQL rules: in SQL held in a JSON or code string,
  where a line break or tab is written as an escape (a backslash, then `n`,
  `r` or `t`), a statement or a `WHERE` that starts right after an escape is
  read as it is after a real line break or tab. A `DELETE` or `UPDATE` whose
  `WHERE` starts a new line that way is no longer flagged. An escape whose
  backslash is itself escaped is not read as one.
- `artzain audit verify --help`, and the docstrings of `cmd_audit_verify` and
  `artzain.audit_verify`, said the check needs zero server trust. The verifier
  checks signatures against public keys that travel inside the bundle, so trust
  in the producing server drops out only at `VERIFIED, ATTESTED`, which needs
  the signing keys to chain to the pinned CogNEXUS Evidence Root. This release
  pins no Evidence Root, so an intact bundle reports `VERIFIED, SELF-ATTESTED`
  unless `--root-fingerprint` supplies a test root. The help now says so. No
  verdict changes.
- `artzain audit verify --root-fingerprint`: an `ATTESTED` verdict went on to
  say the signing keys chain to the CogNEXUS Evidence Root, straight after
  warning that the supplied root is not the published one. It now names the
  root you supplied, as `artzain licence verify` already does. The `--json`
  output is unchanged and still reports `root_fingerprint_overridden`.
- Policy enforcement, on a tool call that is still JSON: the approval escape
  read markers in the JSON text and measured its window there. A hex digit of
  a string escape could complete a marker the tool never reads, and the call
  was allowed. `json.dumps` writes each non-ASCII character as six characters,
  so a marker inside the window in the text the tool reads could sit outside
  it, and the call was denied. An escape now counts as the character it stands
  for, and a hex digit of an escape is not a letter of a marker. Readings
  whose escapes are already written out are unchanged, so a marker only a
  deeper reading brings near a match still does not approve it.
- The policy approval escape no longer treats a marker in a repeated JSON
  key's dropped value as approval of the value a parser keeps. `json.loads`
  keeps the last value and some parsers keep the first; a marker in the other
  value never reaches that tool. A marker in a neighbouring argument still
  approves, at the same distance.
- `root_fingerprint_overridden` compared a caller-supplied Evidence Root
  fingerprint to the built-in pin as raw strings. The certificate check
  already ignores case and surrounding whitespace, so restating the pinned
  fingerprint in upper case or with spaces around it still verified
  `ATTESTED` but was reported as a different root: `artzain audit verify`
  warned that it was not the published CogNEXUS Evidence Root, and `--json`
  set `root_fingerprint_overridden` to true. The flag now uses the same
  comparison as the certificate check. `evidence_root_fingerprint` is that
  normalised fingerprint, on `artzain audit verify` and
  `artzain licence verify`.
- `artzain audit verify`: an `ATTESTED` verdict whose certificate chain
  carries a note (a tampered issuing certificate beside a valid one, for
  example) left that note off the text output. It now prints "Notes on the
  certificate chain:" and each reason, as `artzain licence verify` already
  does. Verification, the verdict, and the `--json` fields are unchanged.
- The prompt-injection screen's `credential_exfil` rule for a request to
  search a connected service (Google Drive, Slack, Box and others) for
  credentials found a service name inside a longer word: "box" in "inbox",
  "mailbox", "sandbox", "TextBox" or "password_box", and "g suite" in
  "testing suite" or "5G suite". So honest text such as "Search the inbox for
  messages; needs an access token.", "List mailbox folders. Requires a secret
  key." or "Find files in the sandbox. Uses your access token." came back
  `high` (`deny`). A service name no longer counts straight after an ASCII
  letter, nor "box" after an underscore or "g suite" after a digit, unless
  that character ends a backslash escape such as `\n` in JSON text read as
  written. Box, Dropbox and the other services named on their own are found
  as before. The rule's entry in `matched_patterns` quotes the start of its
  pattern, so it reads differently.
- Prompt-injection screening: the credential-exfil rule for a verb, a connected
  service, and a credential word retried the gap before the credential from
  every service after every verb. It now matches the same text, including the
  service-name anchors, and reports the same span, in linear time. The pattern
  text recorded on that match changes.
- Policy enforcement (`PolicyEnforcementEvaluator`, `screen_client_policy`):
  the approval escape judged a pattern's matches one after another, each
  approved by a marker near any part of its matched text, so an approved match
  could cover commitments that its matched text overlapped. Every place a
  pattern matches is now judged, a match that starts inside another one
  included, and each needs a marker near where it starts.

### Changed

- `PolicyEnforcementConfig.approval_window_chars` (default 160) is measured
  from where each match starts, before or after it, however far the match
  runs; after a match it used to count from the match's end. An approval
  written after a long commitment has to end within that distance of the
  commitment's first character. A rule pattern that opens with an open-ended
  repeat such as `.*` matches from every position the repeat can start at
  (for `.*`, from the start of the line up to where the rest of the pattern
  last matches), and each of those needs a marker within that distance.
  `approval_window_chars=0` approves nothing; it used to mean a marker inside
  the match.
- `PolicyEnforcementConfig.approval_max_matches` counts matches one after
  another, without overlap, each looked for from where the previous one ends
  (one character further on after an empty match); for a pattern that can
  match an empty string this count can differ from what `re.finditer`
  returns. A pattern for which more than `approval_max_matches` places inside
  its longer matches have to be checked one at a time is a finding too; for a
  pattern whose matches do not all start with at least three fixed
  characters, each group of separately approved commitments inside one longer
  match counts as such a place.
- Offline `decide(kind="model_output")` reads a reply that is JSON the way it
  reads a tool call. A payload counts as JSON when, after any whitespace, it
  opens as an object with its first key, as an array with its first value, or
  as a single JSON string that is the whole reply. The destructive-action,
  injection and policy votes then read it as sent and also read every string
  in it JSON-decoded, which is the text a JSON parser hands the caller. The
  engine's privacy guardian and EU AI Act overlay do the same, and the
  privacy guardian also reads each object member as a `key: value` line. A
  reply has no tool name, so the policy vote does not apply
  `conduct_client_context`; a client word in a JSON key still names a client
  for the conduct rules. Before, those votes other than destructive-action
  and injection read only the JSON text as sent: a phrase or identifier a
  JSON escape split was missed, and non-Latin text and emoji escaped by
  `ensure_ascii` could be denied as an encoding attack.
- Offline `decide(kind="tool_call")`: when a value in a call holds JSON that a
  strict parser does not read, such as a document cut short, the conduct rules
  looked for a client only in that text and in its strings decoded once. The
  policy vote's decoded text also shows the strings of JSON inside those
  strings, so a client it showed there did not count, and profanity elsewhere
  in the call was allowed. Such JSON is now read as text, keys included, as the
  vote decodes it: down to the third level of JSON inside strings, and up to
  its first string that does not decode. JSON nested in strings past the third
  level is read as before.

### Changed

- A JSON `model_output` reply's strings draw what a tool call's arguments
  draw. Each string is read on its own, and each list of strings is also read
  joined with spaces, so a keyword or tag list can be denied. A line of only
  `---`, `###` or three backticks inside a string is a `medium` delimiter
  finding (`review`). More than 1024 distinct strings and lists of strings, or
  JSON nested in strings more than three levels deep, is a `high` finding
  (`input.too_many_strings`, `input.nested_too_deep`).
- `artzain.tool_call_contract` adds `reads_decoded(payload_kind, payload)`,
  which says whether the screens read a payload JSON-decoded as well as sent:
  always for `tool_call`, and for `model_output` when it is JSON as above.
  The engine's policy, privacy and EU-overlay votes use it too.
- `artzain init --framework mcp` and `--framework openclaw`: the generated
  comment about the payload kind says `model_output` would skip the
  tool-contract check. It said a call sent as `model_output` would be screened
  as prose, which is no longer so.

## 0.6.24

### Fixed

- Destructive-action guard: the `git.push_force`, `git.reset_hard`,
  `git.clean_force`, `git.branch_delete`, `fs.dd_to_disk`,
  `docker.system_prune_volumes`, `kubectl.delete_all`, `terraform.destroy` and
  `aws.s3_rb_force` rules could take time quadratic in the length of crafted
  text, in `screen_action()` and in offline `decide()` votes. They now take
  linear time and fire on the same inputs as before; for some inputs a
  finding's excerpt shows a different part of the text than earlier versions
  did.
- The prompt-injection screen's bidi reordering findings, added in 0.6.21
  (`token_smuggle:bidi_override`, `token_smuggle:bidi_rtl_over_ltr`), are
  revised. They flag far less of the right-to-left formatting that locale
  formatters and UI frameworks (Fluent, Apple's Foundation, MessageFormat 2,
  Android, Chromium) write around values, and no longer flag an LRO around an
  amount whose currency sign is right to left. Groups of digits that a
  right-to-left isolate or embedding lays out in the other order count as
  left-to-right text, only right-to-left letters and digits count as
  right-to-left text, and a first-strong isolate is right to left whenever its
  first strong character is, as the bidirectional algorithm decides it. The
  work spent reading bidi controls has a bound.
- Offline `decide(kind="tool_call")`: the conduct rules find a client in a
  call's values, not in its argument or tool names. Profanity in a call was a
  `CONDUCT-PROFANITY-CLIENT` finding, `critical` and so `deny`, whenever an
  argument or the tool had a name such as `account`, `customer` or `client`,
  though no value named a client: an internal message with an `account`
  argument, say. A client named in the call's values, as the screens read
  them (JSON inside strings to three levels), still makes profanity in the
  call a finding, and so does an argument name that holds the profanity and
  the client word together. Profanity and insults are found in names and
  values alike, as before, a payload that is not JSON is read as text, and
  no call is judged more strictly than before.

### Changed

- `artzain.tool_call_contract.conduct_client_context(payload)` says whether a
  tool call names a client for the conduct rules, or returns `None` for a
  payload a strict JSON parser does not read. `evaluate_conduct` and
  `PolicyEnforcementEvaluator.evaluate` take an optional `client_context`:
  `False` says the client words in the text name no client. It never adds a
  client the text does not name. `evaluate_tool_call_policy` passes the
  call's, so an evaluator given to it must accept that keyword.
- README "Gating tool calls": says the conduct rules count a client word in
  any value of the call, and an argument or tool name only when it holds the
  profanity as well.

## 0.6.23

### Fixed

- `decide()` raised `UnicodeEncodeError` instead of failing closed when the
  payload held an unpaired surrogate (half of a UTF-16 pair, which
  `json.loads` makes from a lone escape and `json.dumps(..., ensure_ascii=False)`
  keeps). Offline it came from the prompt-injection detector's audit hash,
  which raised again inside the detector's own fail-closed handler; online
  from encoding the request body, outside the handling that turns failures
  into `DecisionError`. A caller that treats `DecisionError` as deny got an
  uncaught exception. Offline `decide()` now returns `deny`, and online it
  raises `DecisionError` without sending anything. A `context` that does not
  serialize to JSON, because of a type `json` cannot write or nesting too
  deep for it, also raises `DecisionError` before sending, and an offline
  guard that raises becomes a `deny` vote carrying the error.
- `PromptInjectionDetector.detect()`, `screen_user_input()`,
  `screen_external_content()`, `screen_tabular_payload()`,
  `screen_client_policy()` and `evaluate_system_prompt()` raised
  `UnicodeEncodeError` on text holding an unpaired surrogate, and the
  helpers also raised when one was in `source`, `user_id` or another field of
  the event they write. They return a result now. A surrogate in any field of
  an event becomes U+FFFD in every copy of it: the JSONL line, the `on_event`
  record and the cloud event, which one surrogate in `agent_id`, `source` or
  `user_id` used to keep from being sent.
- A surrogate in the prompt a screening helper notes for cloud events made
  every later cloud event from the process fail to send, `agent_kill_switch`
  included, with only a warning in the log. The noted prompt is stored with
  the surrogate replaced.

### Changed

- The prompt-injection detector, the destructive-action guard and the policy
  evaluator refuse text holding an unpaired surrogate, because no screen can
  say what a tool that drops, replaces or rejects the character will read.
  The detector returns CRITICAL `encoding:unpaired_surrogate`, the guard adds
  a CRITICAL `input.unpaired_surrogate` match (`screen_agent_action()` trips
  the kill switch on it), and the evaluator, given at least one rule, adds a
  critical `INPUT-UNPAIRED-SURROGATE` finding (`screen_client_policy()`
  always adds the conduct rules). Text a JavaScript client cut in the middle
  of an emoji holds one, so cut strings by code point before screening them.
- The tool-call screens read a surrogate in a decoded argument as it is.
  0.6.16 to 0.6.22 replaced it with U+FFFD first, so a tool call that carried
  one as a JSON escape, the way `json.dumps` writes it by default, was allowed;
  it is refused now, like the same call serialized with `ensure_ascii=False`.
  When a payload ends inside a string, as a cut payload does, a high surrogate
  escape whose low half the end cut off is dropped with it, as an incomplete
  trailing escape already was, rather than read as a lone surrogate.
- Hashes of screened text (`input_sha256`, `payload_sha256`, `text_hash`,
  `prompt_hash`) encode with `surrogatepass`: the digest of valid text is
  unchanged, and each text holding a surrogate gets its own.
- `artzain.audit_chain.MerkleAuditChain.append` writes a record holding an
  unpaired surrogate, in a value or a key at any depth, with the surrogate
  replaced by U+FFFD, where it raised `UnicodeEncodeError`. A key cleaned into
  one the record already has takes a `#2` suffix, so no value is lost. A record
  without one is written byte for byte as before.

## 0.6.22

### Added

- `artzain registry list/export --source grokbot` — the Agent Wrangler
  Grok Bot host origin.

## 0.6.21

### Fixed

- `decode_strings` includes the decoded prefix of a JSON string that is never
  closed at the end of the payload (a cut inside the last string). An
  incomplete trailing escape is dropped; a bad escape in the middle still
  stops the reading. Screens that use those strings therefore see a line
  break JSON wrote as an escape, even when the payload was cut inside that
  string.
- Offline `decide(kind="tool_call")`: argv-style command reconstruction no
  longer depends on the duplicate-key JSON parser accepting the whole call.
  When that parser cannot take a nested payload that a plain parse still
  accepts, the command is still rebuilt and screened, including when the
  current thread is already out of stack. Repeated keys still keep every
  value when the duplicate-key parser accepts the call.
- The prompt-injection screen flags bidi controls that change the order a
  person sees from the order a model or tool reads. An LRO or RLO around
  letters or digits it lays out in the other direction (a file name that
  shows `.pdf` and ends in `.exe`) is `token_smuggle:bidi_override`. An RLI,
  an RLE, or an FSI made right to left by a mark, around text with no
  right-to-left letter, is `token_smuggle:bidi_rtl_over_ltr`. Both are
  `medium`, which is `review`, except under the permissive `tabular` preset,
  which does not report them. A control left open before a line break is read
  into the next line as well, as HTML lays it out. Right-to-left text with the
  marks, embeddings and isolates formatters write, an LRO around a number, and
  an override around text of its own direction are left alone.

## 0.6.20

### Fixed

- Offline `decide(kind="tool_call")`: the policy-enforcement vote reads a call
  the way its tool receives it, as the destructive-action and injection votes
  have since 0.6.16. Besides the serialized JSON, it reads the call with the
  escapes in its strings written out in place, once for the call's own strings
  and once more for each level of JSON inside strings, up to three levels, so
  the conduct rules judge the words the tool would send. Some abusive language
  inside arguments that earlier versions allowed is now denied: language toward
  a customer, also when the customer is named in a different argument, and
  insults directed at a person.
- `artzain.pii_detector.scan_text` counts a passport number only when it
  contains a digit. Any six to nine letters after the label counted before,
  so `passport: pending`, `passport country: France` and a bare
  `passportNumber` each read as a passport number. A sentence with a number
  counted the same way, through the word after the label; `passport number
  is`, `passport details:` and `passport number -` before the number are
  now read as such. Other words between the label and the number
  (`passport renewed, number C01X00T47`) no longer count, and neither does a
  number of letters only, which a German document issued before November 2023
  can exceptionally have.
- `scan_text`, `redact_text` and `luhn_ok` check digits of other scripts by
  their value. The card checksum read them as if ASCII, and the never-issued
  SSN ranges were compared as ASCII text, so a Luhn-invalid order number in
  fullwidth digits could count as a card and `900-00-0000` in Arabic-Indic
  digits as an SSN.
- `artzain.pii_detector.scan_text()` counts a passport number or a date of
  birth after more of the ways its label is written: `No.` or `Num.` with an
  abbreviation point, the dotted initials `D.O.B.`, a parenthesised note after
  the label such as its abbreviation or a date format (`Date of birth (DOB):`),
  and up to two marks between the label and the value, where a hyphen, an en
  dash or an em dash now counts as well as `:` and `#` (as in `DOB -` or
  `:-`). Every label form that counted before still counts.
- The `KillRecord` that `screen_agent_action()` writes when it trips the kill
  switch can be serialized as JSON. Each entry in its `matches` held the
  guard's `ActionSeverity` enum, so `json.dumps()` of `KillRecord.to_dict()`
  or `recent_activations()` raised `TypeError`, which is what an `on_kill`
  callback storing the record as JSON hit.
- The prompt-injection screen now finds an instruction hidden in the base64 of a
  binary file when its words are disguised with non-text bytes both inside and
  between them at once. The screen already read such bytes two ways — with the
  non-text characters removed, which rejoins a word split by them, and read as
  spaces, which separates words run together by them — but an instruction that
  used both tricks together defeated each reading on its own. A word's letters
  may now be interrupted by non-text characters and its word gaps may be non-text
  as well as whitespace. The search runs in linear time and adds no findings on
  binary files (certificates, keys, images, archives, random bytes).

### Changed

- `artzain.tool_call_contract` adds `decoded_texts` (a call with the escapes in
  its strings written out in place and a line break in place of the comma or
  bracket after each string, once for the call's own strings and once more for
  each level of JSON inside strings, none longer than the call),
  `evaluate_tool_call_policy`, which reads a call as sent and as each of those
  texts, and `combine_policy_reports`, which folds the policy reports of several
  readings of one payload into one, telling rules apart by id, title, category,
  severity and summary.
- README "Gating tool calls": names the policy and PII screens among those that
  read a call's strings JSON-decoded, says which screens read the strings
  together, and that the PII screen runs on the engine only.
- `artzain.tool_call_contract` adds `member_text`, which writes each object
  member of a tool call as a `key: value` line, and `scan_tool_call_pii`,
  which counts PII in a tool call as sent and in those lines. Detectors that
  count a value only after its label, such as `dob: 1990-01-01`, see the
  argument's name as the label: `{"dob": "1990-01-01"}`,
  `{"date_of_birth": "1990-01-01"}` and `{"guest1_dob": "1990-01-01"}` count
  as a date of birth. A key is read as its words only, so a key never adds an
  identifier. Values are read decoded, so an identifier the call's JSON
  escaping hid in a value is counted too. `null`, `true`, `false`, `NaN` and
  numbers of fewer than four digits are not read as values; a string flag is,
  so `{"reset_password": "email"}` counts as credential material, as `reset
  password: email` does. A call the parser does not read (it is not JSON,
  or it nests too deep) is read whole without labels: its strings, keys
  included, decoded, and the text between them as it is. A string that
  looks like JSON and does not parse is read as the tool receives it, with
  each string in it that holds an escape also decoded. Offline `decide()`
  runs no PII screen, so its decisions are unchanged; the engine's privacy
  vote reads the member lines for `payload_kind="tool_call"`.
- In a `KillRecord` from `screen_agent_action()`, each match's `severity` is
  the string value (`"critical"`), as in `ActionScreenResult.to_dict()`, not
  an `ActionSeverity`. Compare it with `ActionSeverity.CRITICAL.value`, not
  `ActionSeverity.CRITICAL`.

## 0.6.19

### Fixed

- The prompt-injection screen's multi-turn-escalation check used an unbounded
  gap in one phrase pattern, so scanning a long single line took time quadratic
  in its length. The gap is now bounded: the scan runs in linear time and the
  pattern joins the decoded-bytes search. It still matches the phrase across a
  normal sentence-length gap.

## 0.6.18

### Fixed

- `artzain.pii_detector.scan_text()` could take time quadratic in the length
  of crafted text aimed at its passport, date-of-birth or email detectors, so
  a large enough input held a CPU for a long time. Those patterns now run in
  linear time and match the same text as before. The engine runs the same
  scan on every decision's payload. `redact_text()` and `minimize_record()`
  use none of these patterns and were not affected.
- Offline `decide(kind="tool_call")` reconstructs an argv-style array of a tool
  call more completely before the destructive-action screen reads it as the
  command it runs. An array of two or more strings is read as one command, its
  tokens joined with spaces the way an argv list runs, and more argument shapes
  that earlier versions did not reconstruct are now covered; a nested list or
  object is read for arrays of its own, and a list that is not a command — such
  as a table row of a label and a value — is left alone. Single-token argv is
  unchanged (`["rm", "-rf", "/"]` reads as `rm -rf /`), the whole array is always
  read as one command line, and the serialized call is still read as sent, so
  what was caught before is still caught.
- Destructive-action guard: the `rm` rules (`fs.rm_rf_root`,
  `fs.rm_rf_generic`) read an `rm` command's arguments one word at a time, and
  a command ends at a line break, a quote, a backslash, a `#` or a shell
  separator, so a word in another field or line is not one of rm's operands.
  Some recursive removals that 0.6.17 screened as `none` are now `critical` or
  `high`, in `screen_action()` and in offline `decide()` votes; a batch of
  false positives (a neighbouring JSON field, a `#` comment, a `*` that is an
  option's value, a word merely containing r and f such as `-Force`) no longer
  screen as a destructive `rm`. Both rules take time linear in the length of
  the text.
- Policy enforcement (`PolicyEnforcementEvaluator`, `screen_client_policy`):
  the approval escape checked only the first match of each rule pattern. When
  that match had an approval marker within `approval_window_chars`, the
  pattern was suppressed for the whole text, including later matches with no
  marker near them. Every match now needs its own marker, and a pattern with a
  match that has none is a finding. `report.suppressed`, and the audit row's
  `suppressed_rule_ids` with it, keeps one entry per suppressed pattern, with
  the marker near its first match, and no longer lists a pattern that is also
  a finding.
- Policy enforcement: approval markers read the final sigma and the small
  sigma as the same letter, in the text and in the markers, so a Greek marker
  matches an approval written in capitals. A marker that is not a string is
  ignored; it could raise before.
- The prompt-injection screen no longer reads a binary file's base64 as an
  encoded instruction. It decoded every run of base64 and searched the bytes
  for words such as `root`, `admin` or `password` whatever they were, and it
  decoded wrapped base64 a line at a time, so a certificate (a root CA's
  subject says "Root"), a key, or an image or archive with a readable name
  inside came back `high` (`deny`): as `user_input`, and since 0.6.16 in a
  tool call's arguments. The bytes of a binary file are no longer searched
  for those words, so a word inside it, such as a root CA's name, is not a
  match, and base64 wrapped across lines, as in a PEM or MIME body, is
  decoded as one blob, whatever line breaks it uses. Base64 of text is still
  searched, now also when it is wrapped at a width that splits its
  four-character groups, and so is a file that is mostly text, such as a ZIP
  archive of text files stored without compression.
- The prompt-injection screen reads variation selectors and bidi controls as
  characters, however the text was serialized. A run of them was a finding
  only once `json.dumps(ensure_ascii=True)` had escaped it into `\uXXXX`
  escapes; in `user_input`, or in a tool call serialized with
  `ensure_ascii=False`, it passed. Now variation selectors in a run, or
  after a kind of character that does not take them, bidi controls left
  without a partner next to other invisible characters, and strings of four
  or more bidi marks are `token_smuggle:variation_selectors` and
  `token_smuggle:bidi_controls`: `high` (`deny`) from four of them anywhere in
  the input. Emoji presentation and ZWJ sequences, CJK ideographic and other
  standardized variants, and the marks, embeddings and isolates formatters
  write around right-to-left text, empty, adjacent or nested, are left alone.
- Offline `decide(kind="tool_call")`: the England, Scotland and Wales flag
  emoji in a call serialized with `ensure_ascii=True` are no longer an
  encoding attack. The injection vote kept the escapes of their tag
  characters, and twelve escapes in a row read as a hidden run.
- Destructive-action guard, SQL rules: a comment between two keywords now
  counts as the separator it is to a SQL engine, so a statement whose keywords
  are split by a block comment, a line comment or a MySQL `/*!...*/`
  executable comment is caught like its whitespace form. Comments are read the
  way MySQL and MariaDB, SQLite, and PostgreSQL and SQL Server (which nest
  block comments) read them. In `DELETE` and `UPDATE` a quoted table name
  (`"orders"`, `` `orders` ``, `[dbo].[orders]`) is read whole, so a `WHERE`
  inside it is not taken for a `WHERE` clause.
- Destructive-action guard: the `DELETE` and `UPDATE` rules took time
  quadratic in the length of some crafted text. All the SQL rules, which now
  read comments, take time linear in it.

### Changed

- Destructive-action guard: `fs.rm_rf_root` rates recursive removal of `/`, a
  glob of root (`/*`, `//`, `/*/`), `~` or `$HOME` `critical` with or without
  force, wherever the target stands among the operands, and a bare `*` (a glob
  of the working directory) as the last operand or when another operand that is
  not an option follows it. Recursive and force are read across separate flags,
  a single cluster (GNU and BSD short flags), or long options in any order; the
  `rm` subcommand of a version-control tool (`git`/`svn`/`hg`/`bzr`) is not the
  filesystem `rm` and is skipped. Without force, `rm` prompts for a
  write-protected file only when its input is a terminal (a recursive removal of
  writable files takes them either way), so force does not change what such a
  removal takes with it. A `critical` vote denies the decision and
  `screen_agent_action()` trips the kill switch, so model output that spells
  such a command is rated the same whether it is a command or a description of
  one. The generic rule (`high`, `fs.rm_rf_generic`) needs both recursive and
  force; the excerpt of either finding is the `rm` command alone.
- `PolicyEnforcementConfig` adds `approval_max_matches` (default 100): the
  approval escape approves at most that many matches of one pattern in a text,
  and a pattern with more is a finding whatever markers sit near them.

## 0.6.17

### Fixed

- The prompt-injection screen (`PromptInjectionDetector`,
  `screen_user_input`, `screen_external_content`, `screen_tabular_payload`
  and offline `decide()`) reads text written in Unicode tag characters
  (U+E0000-U+E007F). Tag characters display as nothing, and most of them map
  one-to-one onto printable ASCII, so text written in them can be read by a
  model but not seen by a person. The screen now applies its rules to that
  text decoded, and the characters are a finding of their own,
  `token_smuggle:tag_characters`: `high` (`deny`) from four tag characters
  anywhere in the input, not counting the ones described below. Below that it
  is `medium`, which is `review`, except under the permissive `tabular` preset,
  which does not report it.
- Tag characters that do not draw that finding: the flags of England,
  Scotland and Wales (the one recommended use of tag characters), and a piece
  of one of them at the start or end of the text, as truncating, chunking or
  streaming text leaves.
- Tag characters that do draw it, usually at `high`: other subdivision flags,
  which few platforms display, and a flag broken up in the middle of the
  text.

### Changed

- `artzain.prompt_injection` adds `RGI_EMOJI_TAG_SEQUENCE_RE`, which matches
  the three flag emoji that do not draw the tag-character finding.

## 0.6.16

### Fixed

- `artzain local`: the rendered `compose.yaml` set seven enforcement-posture
  flags to `observe`, which none of them accepts (`observe` is a
  `COGNEXUS_THROUGHPUT_MODE` value). The engine fell back to its code
  defaults, which was the intended advisory posture, but logged a WARNING
  on every read: four on each decision request from an unregistered agent,
  seven on each OWASP scorecard fetch. The template now writes the code
  defaults explicitly (`advisory`, `review`, `allow`, `permissive`). Run
  `artzain local up` once after upgrading the package to apply them.
- `artzain local`: a variable exported in the shell that runs the CLI no
  longer overrides the workspace `.env`. Compose ranks the shell above
  `--env-file`, so a leftover `JWT_SECRET_KEY` or `POSTGRES_PASSWORD`
  export replaced the install's generated value. The CLI now keeps every
  variable `compose.yaml` interpolates out of its compose calls.
- `artzain init --framework crewai`: the generated `@governed` wrapper sent
  `{"tool": ..., "args": [...], "kwargs": {...}}`. The engine's tool-call
  contract check accepts `args` as a name for the argument object, found a
  list, and rated the call `high` ("arguments are not a JSON object"), so
  every online call from the scaffold went to `review`. (Offline the calls
  were allowed, because offline `decide()` runs no contract check.) The
  wrapper now binds the call to the tool's signature and sends
  `{"tool": <action>, "arguments": {<parameter>: <value>}}`, the same payload
  whether CrewAI passes arguments by keyword or by position. The tool name is
  the `action` given to `@governed`. Files generated by an earlier version
  keep the old wrapper: apply the change by hand, or regenerate with
  `artzain init --framework crewai --force`, which overwrites the file.
- `artzain init --framework crewai` and `--framework mcp`: the tool-call
  payload is serialized with `ensure_ascii=False`. With the default, non-Latin
  text and emoji in an argument became `\uXXXX` escapes, and the injection
  screen denies four or more of those in a row as an encoding attack, online
  and offline. A Cyrillic word, four CJK characters or two adjacent emoji were
  enough.
- `screen_agent_action()`: with the default `raise_on_critical=True`, a
  critical match raised `AgentKilledError` inside `trip()`, before the
  `agent_kill_switch` event was sent, so a kill that stopped a run never
  reached the cloud event log or the dashboard. The event is now sent after
  the trip is recorded and before the error is raised; the error and the kill
  record are unchanged. `raise_on_critical=False` already sent the event.
- Offline `decide(kind="tool_call")` screens a call the way its tool receives
  it. Besides the serialized JSON, the destructive-action and injection votes
  read every string in the call JSON-decoded, keys and values, including JSON
  inside a string such as a stringified `arguments` (up to three levels). Some
  commands inside arguments that 0.6.15 missed are now caught, and most
  non-Latin text and emoji escaped by `ensure_ascii` is no longer denied as an
  encoding attack. The destructive-action vote still reads the call as sent, so
  what it caught before it still catches, and also reads each array of strings
  joined with spaces, as an argv list runs. The injection vote reads the call
  with the escapes of visible characters written out, so escaped text is judged
  by its characters.

### Changed

- `artzain local`: each posture flag in `compose.yaml` reads
  `${VAR:-default}`, so a line in the workspace `.env` (for example
  `COGNEXUS_UNREGISTERED_AGENTS=deny`) changes it and survives upgrades. An
  export of the same variable in your shell does not override that line.
  Before, the flags were fixed in a file every `up` rewrites, so enforcing
  one, including the three the SOC 2 bundle's promote gate requires,
  lasted only until the next `up`.
- README, "Gating tool calls": when the bundle's `resolution` line is what
  stops an undeclared tool, the decision's `reasons` names the tool and says
  the bundle escalated the call. The section used to say `reasons` stays empty
  in that case; the engine now fills it in.
- An argument's text now draws the injection findings the same text draws on
  its own (an argument that is itself valid JSON, through its decoded strings).
  A line of only three or more `-` or `#`, or of three backticks, is a
  `medium` delimiter finding (`review`). A run of four or more `\xNN` or
  `\uNNNN` escapes written out as text, or base64 whose bytes contain a word
  such as `root` or `admin` (line-wrapped base64 like a PEM certificate
  included), can be a `high` encoding finding (`deny`).
- A tool call with more than 1024 distinct strings draws a `high`
  `input.too_many_strings` finding (the strings past that are screened
  together), and JSON nested in strings more than three levels deep draws a
  `high` `input.nested_too_deep` finding.
- `artzain.tool_call_contract` adds `decode_strings`, `unescape_non_ascii`,
  `screen_tool_call_action` and `detect_tool_call_injection`;
  `artzain.destructive_action_guard` adds `combine_screens`, which folds
  several screens of one payload into one result and keeps a screen's internal
  failure `critical` (`guard.error`) whatever rules are disabled.
- README "Gating tool calls": drops the note that the destructive-action guard
  is tuned for commands as written, says what decoded screening means for
  argument text, and keeps recommending `ensure_ascii=False`.

## 0.6.15

### Changed

- README: new "Gating tool calls" section for putting `decide()` into an
  agent's tool loop. It covers the mapping from a tool call onto a decision
  (`kind="tool_call"`, the whole call as the payload, serialized with
  `ensure_ascii=False`), OpenAI-style and Anthropic examples that fail closed
  on `DecisionError`, covering every tool through the dispatcher, and the
  policy-bundle snippet that stops undeclared tools. Documentation only; no
  code changes.

## 0.6.14

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `a2a` origin (FR-12 v5 slice 4: A2A agent-card discovery —
  the public `/.well-known/agent-card.json` of each configured endpoint,
  one row per card, identified by the endpoint).

## 0.6.13

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `google` origin (FR-12 v5 slice 1: Google Cloud discovery —
  Vertex AI Agent Engine deployments inventoried per project × region over a
  service-account key).

## 0.6.12

### Fixed

- `artzain.pii_detector`: the `ssn` detector now matches the space and dot
  separated forms (`536 22 1948`, `536.22.1948`) as well as the hyphenated
  one, and no longer misses an SSN glued to an underscore
  (`employee_536-22-1948`) — the previous `\b` word boundary treated `_` as
  part of the word. A separator is still required: bare nine-digit runs are
  tracking numbers, routing numbers and ZIP+4 far more often than SSNs, and
  `redact_text` rewrites what it matches. Ported from the Agent Governance
  Toolkit credential redactor (microsoft/agent-governance-toolkit#3531).

## 0.6.11

### Changed

- `cloud`: the HTTP 401 warning names where the base URL came from
  (`configure(base_url=...)`, `COGNEXUS_API_BASE_URL`, the credentials
  profile, or the default) instead of printing the URL. The profile that can
  hold `base_url` is the file that holds the API key, so nothing read from it
  belongs in a log line.

- The package version has one home: `artzain.__version__` in
  `src/artzain/__init__.py`. `pyproject.toml` now declares `version`
  dynamic and hatchling reads it from that file, so the wheel metadata
  and `__version__` cannot disagree. Release tooling (the bump script,
  the tag-matches-version check, the drift guard) reads the same file.

- The CLI and GUI now identify honestly as `artzain-python-sdk/<version>`
  by default: `COGNEXUS_SDK_BROWSER_HEADERS` defaults to `0` now that the
  CDN allowlists that User-Agent on `/api/*` (verified 5 Sep 2026: an
  honest login attempt gets the application's 401, a generic client gets
  the edge's 403). Set the variable to `1` only for an edge that still
  challenges non-browser clients; the browser-like branch and the switch
  are scheduled for removal in a later release.

- `policy_enforcement.ClientPolicyRule` compiles its `violation_patterns`
  once per rule instance instead of on every
  `PolicyEnforcementEvaluator.evaluate` call. Up to 80 rules x 6 patterns
  previously relied on the stdlib `re` cache (512 entries) and were
  recompiled on every screen once it was evicted. Public fields,
  `to_dict()` output, and match results are unchanged.

- Exception hygiene across the SDK: every `raise SystemExit(...)` inside an
  `except` block in the CLI now chains the original error (`from exc`), and
  16 `try/except: pass` sites (CLI, GUI, `cloud`, `decide`, `audit_chain`,
  `_helpers`, `pii_detector`) now log the swallowed error at DEBUG on the
  module's `artzain.*` logger instead of dropping it silently; the
  seventeenth, `prompt_injection`'s base64 probe, catches `ValueError` only
  (the only thing `b64decode` can raise there). No new
  exception escapes and no default output changes. Ruff rules `B904` and
  `S110` are now part of the package's lint gate.

- `policy_enforcement`: `rules_from_context_items` no longer reads
  `metadata.web_link` / `metadata.url` — the value was never used (both
  branches produced the subject) and the source ref is the document
  subject, as before. The module header no longer carries the third-party
  notice of the vendored modules; it is CogNEXUS-original code.

- `run_quickstart_demo` docstring points at `scripts/artzain_harness.py`, the
  new home of the manual harness that used to sit at the repository root as
  `test_artzain.py`.

### Fixed

- `artzain.kill_switch.trip` now appends to and counts the auto-panic window
  under `_global_panic_lock`, and flips the global-panic flag in the same
  critical section. Concurrent CRITICAL trips could previously raise
  `RuntimeError: deque mutated during iteration` instead of
  `AgentKilledError`, and two threads could both trip the global panic. The
  audit ring, log line and `on_kill` callback still run after the lock is
  released.

- `prompt_defense`: the five agent-era vectors adopted on 30 Jul 2026
  (`encoding-injection`, `cross-agent-auth`, `least-agency`,
  `skill-provenance` at `high`; `transaction-guardrails` at `critical`) now
  have an explicit entry in `PromptDefenseConfig.severity_map`; they used to
  fall through to the `"medium"` default. The module text no longer claims
  "12 attack vectors" — the count is `VECTOR_COUNT` (20).

- `DestructiveActionGuard.screen()` can no longer be padded past: payloads
  over the 256 KB scan window are now regex-scanned in both a head and a
  tail window (a match visible from both is reported once), and the
  truncation itself is reported as a HIGH finding, `input.truncated`
  (`TRUNCATION_RULE_ID`), whose excerpt names the scanned and total byte
  counts, so a caller that fails on HIGH cannot be bypassed by 256 KB of
  filler before a `DROP TABLE`. Inputs within the window return exactly
  the same results as before.

## 0.6.10

### Changed

- One header policy for every outbound request: `artzain.cloud._sdk_headers`
  now owns the User-Agent / fetch-metadata set the CLI and GUI send, instead
  of three hand-rolled copies of a Chrome User-Agent and a forged
  `Sec-Fetch-Site: same-origin`. `COGNEXUS_SDK_BROWSER_HEADERS` selects the
  set: `1` (the default for now, so nothing changes on the wire) keeps the
  browser-like headers the CDN/WAF still requires; `0` sends the honest
  `artzain-python-sdk/<ver>` identity. The default flips to `0` once the CDN
  allowlists the SDK User-Agent (see `docs/runbooks/supply-chain.md`).
  Telemetry (`post_sdk_event`, `decide`) was already honest and is unchanged.

- Cloud telemetry (`post_sdk_event`, `post_policy_human_decision`) no longer
  starts a daemon thread and opens a fresh TLS connection per event. Rows are
  queued (bounded, 1,000 entries) for a single lazily-started background
  thread that sends them over one reused keep-alive `http.client`
  connection, reconnecting on error and honouring `HTTPS_PROXY`. Callers
  never block: when the queue is full the row is dropped and counted
  (`artzain.cloud.dropped_cloud_events()`). `flush_cloud_events(timeout_sec)`
  now waits for the queue to drain; the `atexit` flush is unchanged.

### Fixed

- `artzain gui`: the API-key bootstrap now surfaces the platform's MFA
  challenge. `POST /api/auth/token` returns `mfa_required` instead of a
  session for accounts with two-factor authentication enabled; the local
  client previously treated that as a failed exchange and showed a false
  "No API key found" message. It now explains that the key alone cannot open
  a session on a 2FA account and points at the hosted dashboard.

- Destructive-action guard: the `fs.rm_rf_root` rule matched its `/`, `~`
  and `$HOME` targets as prefixes, so any absolute path (`rm -rf
  /tmp/build-cache`, `rm -rf ~/.cache/pip`) was rated CRITICAL as a root
  wipe. The target is now anchored to a shell separator or end of input;
  such paths fall through to `fs.rm_rf_generic` (HIGH). `rm -rf /`,
  `rm -rf ~`, `rm -rf $HOME`, `rm -rf / ;`, `rm -rf /*` and `rm -rf *`
  are still CRITICAL.

- Tool-call contract: `inspect_tool_call` no longer raises `RecursionError`
  on a deeply nested payload (e.g. a 50,000-deep array). The depth and
  key-count walks are iterative, the JSON decoder's recursion failure is
  caught at both parse sites, and any remaining recursion failure in the
  inspection path is reported as a `high` (fail-closed) finding.

- Destructive-action guard: the secret redactor in match excerpts only
  rebuilt `key=value` secrets, so a `key: value` secret (`password: ...`,
  `token: ...`) came back unredacted in kill records and the audit log. The
  key name and separator are now kept and the value is redacted for both
  forms.

- Policy enforcement: the approval escape is now bounded. An approval
  marker (`approved by`, `per policy`, ...) only suppresses a match when
  it occurs within `PolicyEnforcementConfig.approval_window_chars`
  (default 160) of the matched span, so a trailing `per policy` no longer
  switches every approval-gated rule off for the whole text. Suppressed
  matches are recorded in `PolicyEnforcementReport.suppressed` (findings
  flagged `suppressed_by_approval_marker` with the `approval_marker`) and
  as `suppressed_rule_ids` on the policy-enforcement audit row.

## 0.6.9

### Fixed

- `verify_chain` now fails a JSONL audit log whose chained entry has no
  `sig`, and one that contains an unsequenced line after the chain has
  started. Both were previously accepted, so a writer with access to the
  file could rewrite an entry, drop its signature (or its `seq`), recompute
  the hashes forward, and still get `chain OK`.
- Destructive-action guard: the `sql.delete_no_where` / `sql.update_no_where`
  rules bound their WHERE lookahead to the statement being screened. A
  `WHERE` in a trailing comment or in a later statement no longer switches
  the rule off; a `WHERE` on a continuation line of the same statement
  still counts.
- Prompt-injection detector: text is NFKC-normalised and stripped of
  invisible characters (zero-width space/joiners, word joiner, BOM, soft
  hyphen) before the pattern pass, so `ign​ore previous instructions`
  and fullwidth `ｉｇｎｏｒｅ` are caught like the plain form. Normalisation is
  recorded as a low-confidence signal, never a finding on its own.
- Prompt-injection detector: the in-object audit trail is a bounded deque
  (`audit_log_size`, default 1,000 records) instead of an unbounded list on
  a long-lived detector.

## 0.6.8

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `openclaw` origin (FR-12 v3 Wave D part 2: OpenClaw
  gateway probe — instance agents listed via the gateway's
  OpenAI-compatible `/v1/models` surface).

## 0.6.7

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `n8n` origin (FR-12 v3 Wave D part 1: n8n agentic
  workflow discovery — AI-cluster and ArtzAIn-gated workflows).

## 0.6.6

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `agentforce` origin (FR-12 v3 Wave C: Salesforce
  Agentforce / Einstein Bot discovery over the existing Salesforce
  connection).

## 0.6.5

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `foundry` origin (FR-12 v3 Wave B part 2: Microsoft
  Foundry / Azure AI Foundry per-project agent discovery).

## 0.6.4

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `anthropic` origin (FR-12 v3 Wave A: Anthropic / Claude
  estate discovery — workspaces, API-key inventory, the Claude Code fleet
  row, and Managed Agents).

## 0.6.3

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  now accept the v2 discovery origins `openai`, `code_scan`, and
  `langgraph`, matching the engine's catalog API (FR-12 v3 Wave 0). The
  CLI had been stuck at the v1.5 origin list, so entries from the three
  v2 sources could not be filtered from the terminal.

## 0.6.2

### Fixed

- `artzain local create-admin` could hang forever instead of creating the
  admin. On Windows `getpass` reads the console device rather than
  `sys.stdin`, so with stdin piped or absent — CI, ssh without a tty,
  scripted installs: the exact headless contexts the command exists for —
  it waited on a keyboard that was not there. A new `--password-stdin`
  flag reads the password from the first line of stdin (`docker login`
  style), and without the flag every password prompt in the CLI
  (`quickstart` sign-up and `local activate` sign-in included) now falls
  back to reading stdin whenever no real console is attached — including
  the `< NUL` redirect that fools `isatty` on Windows. Validation is
  unchanged: under 8 characters still exits 2 with the same message.

## 0.6.1

### Fixed

- A malformed `COGNEXUS_API_KEY` is no longer echoed in full. `artzain
  quickstart` reported an unusable key as `invalid or unreachable
  (<key>…)`, truncating to 14 characters — but the fallback for a value
  shorter than that printed the whole thing, so a mistyped key reached
  terminal scrollback and CI logs verbatim. Anything too short to spare a
  prefix now reads `redacted`; `artzain gui` masks its 8-character
  auto-login hint the same way. Well-formed keys display exactly as
  before. Found by CodeQL on the public SDK mirror.

## 0.6.0

### Added

- `artzain local` — the self-serve in-boundary installer (installer plan
  WS-B). `up` renders a `~/.cognexus` workspace from the stable-channel
  manifest (every image pinned **by digest**, including the postgres base),
  generates real secrets once — and repairs a partial `.env` in place rather
  than ever overwriting values — starts the stack, waits for `/health`, and
  hands off to the `/welcome` first-run page. `doctor` prints one remedial
  sentence per failed check (`--port` handles a busy 8080 without editing
  any file); `status` shows health, trial days remaining, and update
  availability; `upgrade` streams a binary `pg_dump` to `backups/` and
  refuses to proceed without it; `down --purge` (and its alias `reset`)
  demands the install id typed back — persisted at up-time so the guard
  holds even with the stack stopped; `create-admin` is the headless first
  run; `activate` verifies and installs a licence certificate, signing in
  with your dashboard email when no API key is configured — the path that
  keeps an expired trial convertible.
- Mutating `local` commands take a workspace lock, so two concurrent `up`s
  cannot split the generated secrets between `.env` and the database volume.

## 0.5.2

### Added

- The GUI renders Roger's clarify cards ("Did you mean one of these?"):
  when a message nearly matches a platform action, the engine now answers
  with an `action_card` of type `clarify`, and each option is a button that
  sends its canonical phrase as an ordinary message. Before this, such a
  card displayed as a dead "pending" stub with no options. The GUI's card
  builder is pinned to the dashboard's by `scripts/check_roger_dock.mjs`
  in the engine repo, so the surfaces cannot drift silently again.

## 0.5.1

A maintenance release: no behaviour changes. It exists because PyPI is
immutable and `scripts/check_sdk_version.py` refuses a tree that differs from
the published 0.5.0 under the same number.

### Changed

- The package is now linted in CI (`ruff`, E/F/W/I). Five modules changed to
  satisfy it — unused imports removed, import blocks sorted, ambiguous `l`
  loop variables renamed — with no change to any public name or behaviour.
- The README opens with what the package does: the local guards are free and
  offline; `decide()` asks an engine for a governed decision; `audit verify`
  and `licence verify` check evidence offline with three verdicts, and today
  every bundle verifies `SELF-ATTESTED` because the Evidence Root is not yet
  pinned. The guard library documentation follows unchanged.

## 0.5.0

The licence CLI and the rotation-aware verifier. Both were written before
0.4.0 was cut and neither reached PyPI, so 0.4.0 users have a verifier that
cannot read a key handover and no `artzain licence` command at all.

### Added

- **`artzain licence`** — the client half of the offline licence flow:
  `request`, `install`, `attest`, `anchor`, `anchors`, `verify`. Everything
  works on files, with no network at any point. That is a requirement rather
  than an optimisation: a sovereign or air-gapped install exports an
  attestation, a person carries it out on whatever medium they already use,
  and it is verified on the other side.
- **`artzain.licence`** — the module behind it. CSRs, anchor records, Sealed
  Usage Attestations, and three-verdict verification matching the audit
  verifier (`VERIFIED, ATTESTED` / `VERIFIED, SELF-ATTESTED` / `FAILED`).
- **Signing-key handovers in `audit verify`.** A bundle that spans a key
  rotation now carries `key-rotations.json`: countersigned records binding a
  retiring key to its successor. The verifier checks both signatures against
  the public keys carried *inside each record*, not through `keys.json`, so an
  edited bundle cannot choose which of its own claims get inspected.
- `audit verify --json` reports `rotations_checked` and `unexplained_key_ids`.

### Changed

- A bundle whose signed manifest commits `key_ids` now fails if `keys.json` is
  missing one of them. Deleting a key was previously invisible, and it silently
  skipped whatever check would have resolved that key.
- `verify_bundle` reports, without failing, a key that signed records in the
  bundle when no sound handover names it. Reported rather than fatal because a
  second process legitimately signs with its own key — but it is also the shape
  a substitution takes, so the reader gets to decide.

### Compatibility

Bundles exported before any of this still verify exactly as they did. A
handover the bundle cannot check — a key absent from `keys.json`, or
`cryptography` not installed — is reported, never fatal: a supplementary
custody claim must not collapse the verdict for an otherwise intact chain.

## 0.4.0 and earlier

Not recorded here. See the git history on
[CogNEXUSlabs/cognexus-tools](https://github.com/CogNEXUSlabs/cognexus-tools).
