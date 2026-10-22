# Basic and advanced setup design

Status: proposed next-version design; not implemented by the current packages.
This document describes the target behavior. SPEC.md remains the specification
of the current implementation until a versioned protocol update is released.

## Setup experience

After linking Telegram, the account owner chooses a mode before enrollment is
activated. The host application supplies this screen; these libraries supply
the policy and challenge APIs. No frontend framework is required.

> **How would you like to verify actions?**
>
> **Basic**
> Get a short code for the action you are completing. Ask us to send it, or
> open Telegram and request it yourself. One request at a time.
>
> **Advanced — recommended**
> Review the action in Telegram before requesting its code. Keep separate
> requests for different sessions and actions, and cancel requests you do not
> recognize.
>
> Both options use expiring, single-use codes. You can change your choice in
> security settings after verifying your current factor.
>
> [ Basic ] [ Advanced ]
>
> [ Continue ]

Neither option is preselected: the user makes an explicit choice. Setup shows a
summary, performs a test challenge in the selected mode, then saves enrollment
and mode together. Abandoning setup leaves enrollment pending, not enabled.
Push and pull are available in both modes and can be chosen for each request.

The application operator sets a minimum mode: `basic` permits either choice;
`advanced` permits advanced only and explains the requirement. The account owner
cannot override an application requirement. Initial linking still uses the
existing authenticated deep-link or paste flow, with recent first-factor proof
and CSRF protection on the application's state-changing endpoints.

## Behavior by mode

| Behavior | Basic | Advanced |
| --- | --- | --- |
| Push from the website | Yes | Yes, with action details in Telegram |
| Pull from Telegram | `/code` selects the single pending request | `/code` lists pending requests for selection |
| Pending requests | One per account | Up to five per account, separately scoped |
| Website context | Plain action label | Action label and relevant transaction details |
| Telegram context | Action label and short request reference | Action details, request reference, request-code and cancel buttons |
| Sensitive actions | Exact action-specific code required | Exact action-specific code and review step required |
| Universal codes | Never | Never |
| Cancellation | Website | Website and Telegram |

Basic reduces the number of screens and concurrent requests; it does not relax
verification, recovery, hashing or storage guarantees. In basic mode, creating a
second request returns `request_pending`; the same idempotency key returns the
existing request. The user must finish or explicitly cancel it before continuing.
Do not silently replace a pending request from a different session.

Advanced review improves action visibility. It does not make transcribed codes
phishing-resistant, and a Telegram review alone never completes the website action.

## Shared challenge flow

1. The website creates a challenge for a server-selected action, account and
   session. A login uses a restricted pre-authentication session after password
   proof; it must not grant access to the authenticated application yet.
2. The website displays the action and request reference, with **Send code to
   Telegram**, **Get code in Telegram**, and **Cancel request**.
3. Push issues a code for that challenge. Pull resolves that same challenge from
   the linked private chat. If there is no pending challenge, `/code` replies:
   "Start the action on the website first, then request its code here."
4. In basic mode the bot displays the action label and sends the code. In
   advanced mode the bot displays the details first and requires **Request code**.
   Push in advanced mode sends this review card; the button issues the code.
5. The website submits `challenge_id` and code. The server supplies the expected
   account, session and action; it never trusts a purpose chosen in the request.
6. Verification atomically consumes the challenge. The application commits the
   exact authorized operation once, using the challenge ID as its idempotency key.

For advanced withdrawals, show the amount, currency and masked destination.
Bind verification to a digest of the complete immutable transaction. Changing
the transaction cancels the challenge and requires a new one. Display metadata
is derived from server records, escaped for Telegram HTML, and limited to what
is necessary. Do not include passwords, full payment details or session secrets.
Changing a delivery direction must not create a new challenge or reset attempts.

## State and storage contract

Use one canonical, versioned JSON representation in both languages:

```json
{
  "schema_version": 2,
  "challenge_id": "random-opaque-id",
  "user_id": "opaque-account-id",
  "session_binding": "server-keyed-session-digest",
  "factor_version": 7,
  "policy_version": 2,
  "mode": "advanced",
  "purpose": "withdrawal",
  "action_digest": "server-keyed-action-digest",
  "state": "pending",
  "code_hash": null,
  "attempts": 0,
  "created_at": 1800000000,
  "expires_at": 1800000300
}
```

Challenge IDs and button tokens use at least 128 bits of secure randomness.
Store hashes of button tokens; keep callbacks short enough for Telegram's
callback payload limit. Bind each callback to its challenge, linked private
chat, factor version and allowed operation. A callback identifier is not proof
of identity; validate the webhook and the callback sender and chat.

States: `pending -> issued -> consumed`, with `cancelled`, `expired`, and `locked`
as terminal alternatives. Issuance may replace an issued code after cooldown,
but never extends the challenge deadline or resets the cumulative attempt count.
Repeated review callbacks are idempotent. Terminal challenges cannot issue codes.

Default lifetime is five minutes, with five failed attempts total and a
120-second account send cooldown. Enforce a separate account-wide guess limit
across challenges and sessions so advanced mode cannot multiply the guess budget.
Apply endpoint and bot-command abuse limits as well. Validate finite integer
configuration values. Require a strong HMAC pepper stored outside challenge
storage; authenticate the code with its challenge ID, account and factor version.

The store contract must support atomic issue, verify/consume, attempt increment,
cancel, cooldown reservation and callback claim operations. Each operation checks
expiry, current factor version and policy version. Generic get/put/delete is not
sufficient. Use database transactions or Redis scripts, with an explicit durable
strategy for coordinating identity and challenge state across stores.

Persist a consumed authorization result bound to the exact operation, so a crash
between verification and action commit can be retried safely without accepting
the code again. The host application's transaction or durable workflow owns the
operation commit and its idempotency constraint.

## Factor changes, recovery and mode changes

- Replace a chat with a conditional database update/transaction: check ownership
  and the expected factor version, update the binding, and advance the version.
  A failed replacement leaves the original binding intact. Notify after commit.
- Replacement tokens carry the factor version whose possession was proved.
  Unlinking, recovery and replacement advance that version, revoking all older
  codes, callbacks and replacement tokens. Version checks remain necessary even
  if asynchronous cleanup has not run yet.
- Changing modes requires recent factor proof for `change_mode`. Enforce the
  application's minimum, advance the policy version, and cancel pending requests.
  Notify Telegram and record the change in the audit log. Never downgrade through
  a request parameter or silently fall back to basic after an error.
- If Telegram is inaccessible, use the application's explicit recovery process.
  Recovery does not silently weaken the chosen mode or bypass application policy.

## Delivery and webhook processing

Both modes use the same bot transport and queue. Pull still needs an outbound
reply and does not avoid delivery limits. Reserve sends atomically, respect
Telegram retry guidance, and never report delivery success before confirmation.
Use a durable inbox for accepted updates and retry transient processing failures;
claiming an update is not the same as completing it. Invalid updates are rejected.

Keep plaintext codes out of logs, API responses and ordinary queue records. A
delivery worker generates and stores the code hash immediately before sending;
if a retry needs a new code, replace only that challenge's code under its existing
deadline and attempt budget. Use an issuance generation so late failures cannot
delete a newer code. Treat timeouts as uncertain delivery, show retry status,
and ensure eventual retries cannot send or revive cancelled requests.

## Proposed API and rollout

These are proposed interfaces, not currently available methods:

| Operation | Inputs supplied by the application |
| --- | --- |
| `completeSetup` | Enrollment token, selected mode, successful setup proof |
| `createChallenge` | User, server session binding, purpose, immutable action context, idempotency key |
| `requestDelivery` | Challenge ID, authorized session, push or pull |
| `verifyChallenge` | Challenge ID, code, expected session and action context |
| `cancelChallenge` | Challenge ID and authorized session or bound Telegram callback |
| `changeMode` | User, requested mode, current-factor proof |

Persist `verification_mode`, `factor_version`, and `policy_version` with the
identity. The application operator's proposed configuration is
`minimum_mode: basic | advanced`; it is distinct from the account owner's choice.
Keep v2 challenge keys separate from v1 records. Deploy compatible PHP and Node
readers together, invalidate old ephemeral records, and require existing users
to choose a mode at their next authenticated setup step. Never infer that a
legacy universal code can satisfy a v2 challenge. Release this as a breaking
protocol change, with migration instructions and no claim of v1 interoperability.

Acceptance checks before release:

- Both setup choices work; an advanced-only application cannot be downgraded.
- Both delivery directions resolve the intended challenge in both modes.
- Concurrent correct submissions have exactly one successful consumption.
- Concurrent failures cannot exceed the attempt budget or revive consumed codes.
- Different sessions, purposes and transaction details cannot share authorization.
- Failed replacements retain the old binding; factor changes revoke old authority.
- Mode changes, retries and restarts cannot weaken policy or duplicate actions.
- PHP-produced records work in Node and Node-produced records work in PHP.
- Callback replay, group callbacks, delivery timeouts and webhook retries are covered.
