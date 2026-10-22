# telegram-2fa (Go)

Telegram as a second authentication factor for Go 1.21+. Standard library only —
no third-party dependencies at all.

Implements [SPEC.md](../../SPEC.md) v1.0, the same protocol as the
[PHP](../php), [Node](../node) and [Python](../python) packages in this
repository, so all four interoperate against one bot and one store.

```bash
go get github.com/getkampe/telegram-2fa/packages/go
```

```go
import telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
```

---

## Wiring

```go
config, err := telegram2fa.ConfigFromEnv()
if err != nil {
    return err                      // a configuration that cannot be secure
}

service, err := telegram2fa.New(telegram2fa.Options{
    Config:     config,
    Store:      myRedisStore,        // or store.NewMemoryCodeStore(nil) in tests
    Identities: myIdentityStore,     // 3 methods — the only adapter you write
    Telegram:   telegramclient.New(telegramclient.Options{BotToken: config.BotToken}),
    Messages:   telegram2fa.DefaultMessages{},
})
```

`NewConfig` rejects anything that cannot be secure rather than accepting it and
logging a warning nobody reads: a missing webhook secret, an unlimited attempt
budget, a code lifetime measured in days, a `HashPepper` under 32 characters.
The error is a `*telegram2fa.ConfigError` naming the field.

`ConfigFromEnv` reads `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`,
`TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_2FA_HASH_PEPPER` and the optional
`TELEGRAM_2FA_CODE_TTL`, `_COOLDOWN`, `_MAX_ATTEMPTS`, `_APP_NAME`.

### The identity store

Three methods over your own users table, with `database/sql`:

```go
type SQLIdentities struct{ DB *sql.DB }

func (s SQLIdentities) FindByUserID(userID string) (*telegram2fa.Identity, error) {
    row := s.DB.QueryRow(
        `SELECT telegram_chat_id, telegram_linked_at, telegram_enrollment
           FROM users WHERE id = $1`, userID)

    var chatID, generation sql.NullString
    var linkedAt sql.NullTime

    switch err := row.Scan(&chatID, &linkedAt, &generation); {
    case errors.Is(err, sql.ErrNoRows):
        return nil, nil
    case err != nil:
        return nil, err
    }

    // Returned even when no chat is linked: the generation outlives the
    // binding, so a token minted before an unlink stays void after a relink.
    return &telegram2fa.Identity{
        UserID:     userID,
        ChatID:     chatID.String,
        LinkedAt:   linkedAt.Time.Unix(),
        Generation: generation.String,
    }, nil
}

func (s SQLIdentities) Transition(userID, chatID, expected, next string) (*telegram2fa.Identity, error) {
    // The comparison is part of the write. Validating in application code and
    // then writing leaves a window in which a recovery can land and be
    // silently overwritten — which is how a replacement token outlives the
    // enrollment it proved.
    query := `UPDATE users
                 SET telegram_chat_id = $2, telegram_linked_at = $3, telegram_enrollment = $4
               WHERE id = $1 AND telegram_enrollment IS NOT DISTINCT FROM $5`

    if expected == telegram2fa.AnyGeneration {
        query = `UPDATE users
                    SET telegram_chat_id = $2, telegram_linked_at = $3, telegram_enrollment = $4
                  WHERE id = $1`
    }

    result, err := s.DB.Exec(query, userID, nullable(chatID), linkedAt(chatID), next, nullable(expected))

    if isUniqueViolation(err) {
        // The unique index is what actually guarantees one chat per account:
        // two concurrent transitions both pass an application check, and only
        // one can pass the index.
        return nil, telegram2fa.ErrChatAlreadyLinked
    }

    if err != nil {
        return nil, err
    }

    if affected, _ := result.RowsAffected(); affected != 1 {
        return nil, nil        // changed under us; nothing was written
    }

    return s.FindByUserID(userID)
}
```

The matching schema:

```sql
ALTER TABLE users
    ADD COLUMN telegram_chat_id    text UNIQUE,   -- the UNIQUE is load-bearing
    ADD COLUMN telegram_linked_at  timestamptz,
    ADD COLUMN telegram_enrollment text;          -- kept when unlinked, on purpose
```

### The webhook

```go
verifier := webhook.NewVerifier(config)
handler := webhook.NewHandler(webhook.HandlerOptions{
    Service: service, Config: config, Store: codeStore,
    Telegram: client, Messages: telegram2fa.DefaultMessages{},
})

http.HandleFunc("/telegram/webhook", func(w http.ResponseWriter, r *http.Request) {
    if !verifier.Accepts(r.Header.Get(webhook.SecretHeader), r.RemoteAddr) {
        w.WriteHeader(http.StatusForbidden)
        return
    }

    var update webhook.Update

    if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&update); err != nil {
        w.WriteHeader(http.StatusOK)   // malformed: nothing to retry
        return
    }

    if _, err := handler.Handle(update); err != nil {
        // The failure, never the payload: the payload contains the codes.
        log.Printf("telegram-2fa: handler failed: %v", err)
    }

    w.WriteHeader(http.StatusOK)       // always 200 — see SPEC.md 7.5
})
```

Skipping the verifier makes the endpoint accept "this chat id is asking for a
code" from anyone who finds the URL. See
[SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

---

## API

| Method | Purpose |
| --- | --- |
| `StartDeepLink(userID)` | Mint a nonce bound to the account; `.URL` is the `t.me` link. |
| `CompleteDeepLink(token, chatID)` | Resolve a `/start` payload. Single use. |
| `StartPasteLink(chatID)` | Bot side: mint an 8-character code bound to the chat. |
| `CompletePasteLink(userID, code)` | Authenticated page side. Rate-limit this. |
| `StartChatReplacement(userID, code)` | Move to a new Telegram account. Returns a request, or the `VerificationResult` that stopped it. |
| `Push(userID, purpose)` | Issue a code and send it. An empty purpose means `login`. |
| `Pull(chatID)` | The user asked the bot for one; purpose `on_demand`. |
| `Verify(userID, code, purpose)` | Check a code. An empty purpose means `login`. |
| `IsLinked` / `Identity` / `IdentityForChat` | State. |
| `Unlink(userID, code)` | Remove, with proof under purpose `unlink`. |
| `UnlinkAfterExternalProof(userID, reason)` | Remove, when another factor proved it. |

Neither challenge method returns the code: it is generated, hashed into the
store, handed to Telegram and dropped, so a `ChallengeResult` is safe to
marshal straight into a response.

`purpose` names the step a code authorises and is checked on every
verification. There is no "match anything" value, and an empty string means
`login` rather than a wildcard — a default of "compare against nothing" means
the binding does nothing unless every call site opts in, and the call site that
forgets is the one that matters. Constants: `PurposeLogin`, `PurposeOnDemand`,
`PurposeReplace`, `PurposeUnlink`.

Every method returns `(result, error)`. The `error` is for transport and
storage failures; protocol outcomes are in the result's `Error` field, which is
an `ErrorCode` carrying the shared wire strings (`not_linked`, `cooldown`,
`invalid`, …).

---

## Tests

```bash
cd packages/go
go test ./...
CGO_ENABLED=1 go test -race ./...
```

70 tests, standard library only. They include the cross-language fixtures in
[`/conformance`](../../conformance/records.json), which the other three suites
read too, so a field name drifting here fails theirs.

**This port gets the strongest concurrency check of the four.** PHP has no
threads in a request, Node has one event loop, and Python's GIL hides a short
critical section unless the clock is made to yield. Go goroutines are genuinely
preemptible, and `-race` reports unsynchronised access directly rather than
waiting for a bad interleaving to happen to occur.

Both halves of that matter, and both were confirmed: removing the mutex from
`MemoryCodeStore.Take` makes the detector print `DATA RACE` *and* makes the
assertion fail with "exactly one caller may receive the value, 2 did". Each
protection was checked the same way — the store mutex, the conditional
transition, the generation check on acceptance, the proven-generation rule, and
the conditional delivery cleanup. The proven-generation case initially passed
with the protection removed, so a read-counting identity store was added to
target the exact window; without that the suite was passing for the wrong
reason.
