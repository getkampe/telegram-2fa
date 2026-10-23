# kampe-telegram-2fa

Telegram as a second authentication factor for Python 3.10+. Zero runtime
dependencies, no framework assumptions.

Implements [SPEC.md](../../SPEC.md) v1.0, the same protocol as the
[PHP](../php) and [Node](../node) packages in this repository, so all three
interoperate against one bot and one store.

```bash
pip install kampe-telegram-2fa
```

---

## Synchronous, on purpose

This port is synchronous. Django, Flask and any WSGI stack call it directly;
from asyncio, wrap it:

```python
import asyncio

result = await asyncio.to_thread(tfa.verify, user_id, code, "withdrawal")
```

That choice is not laziness. In an event loop an `await` inside a critical
section is a suspension point, and the Node package shipped a bug of exactly
that shape — `take()` awaited its read before deleting, so two concurrent
verifications of one code both succeeded. A `threading.Lock` has no such trap,
and it lets the test suite spawn real threads, which is a stronger check than
interleaving a single loop by hand.

---

## Wiring

```python
from kampe_telegram_2fa import (
    Config, DefaultMessages, HttpTelegramClient, RedisCodeStore,
    TelegramTwoFactor,
)

config = Config.from_env()      # or Config(bot_token=..., webhook_secret=..., ...)

tfa = TelegramTwoFactor(
    config=config,
    store=RedisCodeStore(redis),        # or MemoryCodeStore for tests
    identities=my_identity_store,       # 3 methods — the only adapter you write
    telegram=HttpTelegramClient(config.bot_token),
    messages=DefaultMessages(),
)
```

`Config` validates on construction and raises `ConfigurationError` rather than
accepting something that cannot be secure — a missing webhook secret, an
unlimited attempt budget, a code lifetime measured in days, a `hash_pepper`
shorter than 32 characters.

`Config.from_env()` reads `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`,
`TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_2FA_HASH_PEPPER` and the optional
`TELEGRAM_2FA_CODE_TTL`, `_COOLDOWN`, `_MAX_ATTEMPTS`, `_APP_NAME`.

### The identity store

Three methods over your own users table. With Django:

```python
from kampe_telegram_2fa import ANY_GENERATION, ChatAlreadyLinked, Identity
from django.db import IntegrityError, transaction


def to_identity(row) -> Identity:
    return Identity(
        user_id=str(row.pk),
        chat_id=row.telegram_chat_id or None,
        linked_at=int(row.telegram_linked_at.timestamp()) if row.telegram_linked_at else None,
        generation=row.telegram_enrollment or None,
    )


class DjangoIdentityStore:
    def find_by_user_id(self, user_id):
        row = User.objects.filter(pk=user_id).first()

        # Returned even when no chat is linked: the generation outlives the
        # binding, so a token minted before an unlink stays void after a relink.
        return to_identity(row) if row else None

    def find_by_chat_id(self, chat_id):
        row = User.objects.filter(telegram_chat_id=chat_id).exclude(
            telegram_chat_id=None
        ).first()

        return to_identity(row) if row else None

    def transition(self, user_id, chat_id, expected, next_generation):
        # The comparison is part of the write. Validating in application code
        # and then writing leaves a window in which a recovery can land and be
        # silently overwritten — which is how a replacement token outlives the
        # enrollment it proved.
        query = User.objects.filter(pk=user_id)

        if expected != ANY_GENERATION:
            query = query.filter(telegram_enrollment=expected)

        try:
            with transaction.atomic():
                updated = query.update(
                    telegram_chat_id=chat_id,
                    telegram_linked_at=None if chat_id is None else timezone.now(),
                    telegram_enrollment=next_generation,
                )
        except IntegrityError as error:
            # The unique constraint is what actually guarantees one chat per
            # account: two concurrent transitions both pass an application
            # check, and only one can pass the index.
            raise ChatAlreadyLinked("That chat is already a second factor.") from error

        if updated != 1:
            return None        # changed under us; nothing was written

        return self.find_by_user_id(user_id)
```

The matching model fields:

```python
telegram_chat_id = models.CharField(max_length=64, null=True, unique=True)
telegram_linked_at = models.DateTimeField(null=True)
telegram_enrollment = models.CharField(max_length=64, null=True)  # kept when unlinked
```

### The webhook

```python
from kampe_telegram_2fa import SECRET_HEADER, UpdateHandler, WebhookVerifier

verifier = WebhookVerifier(config)
handler = UpdateHandler(tfa=tfa, config=config, store=store,
                        telegram=telegram, messages=messages)

def telegram_webhook(request):
    if not verifier.accepts(request.headers.get(SECRET_HEADER), get_client_ip(request)):
        return HttpResponse(status=403)

    try:
        handler.handle(json.loads(request.body))
    except Exception:
        # The failure, never the payload: the payload contains the codes.
        logger.exception("telegram-2fa: handler failed")

    return JsonResponse({"ok": True})      # always 200 — see SPEC.md 7.5
```

Skipping the verifier makes the endpoint accept "this chat id is asking for a
code" from anyone who finds the URL. See
[SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

---

## API

| Method | Purpose |
| --- | --- |
| `start_deep_link(user_id)` | Mint a nonce bound to the account; `.url` is the `t.me` link. |
| `complete_deep_link(token, chat_id)` | Resolve a `/start` payload. Single use. |
| `start_paste_link(chat_id)` | Bot side: mint an 8-character code bound to the chat. |
| `complete_paste_link(user_id, code)` | Authenticated page side. Rate-limit this. |
| `start_chat_replacement(user_id, code)` | Move to a new Telegram account, proving the old one. Returns `LinkRequest` or `VerificationResult`. |
| `push(user_id, purpose="login")` | Issue a code and send it. |
| `pull(chat_id)` | The user asked the bot for one; purpose `on_demand`. |
| `verify(user_id, code, purpose="login")` | Check a code. |
| `is_linked(user_id)` / `identity(user_id)` / `identity_for_chat(chat_id)` | State. |
| `unlink(user_id, code)` | Remove, with proof under purpose `unlink`. |
| `unlink_after_external_proof(user_id, reason)` | Remove, when another factor proved it. |

Neither challenge method returns the code. It is generated, hashed into the
store, handed to Telegram and dropped, so a result is safe to serialise
straight into a response.

`purpose` names the step a code authorises and is checked on every
verification. There is no "match anything" value, and the default is `login` on
both sides rather than a wildcard — a default of "compare against nothing"
means the binding does nothing unless every call site opts in, and the call
site that forgets is the one that matters. Constants: `PURPOSE_LOGIN`,
`PURPOSE_ON_DEMAND`, `PURPOSE_REPLACE`, `PURPOSE_UNLINK`.

---

## Testing against it

```python
from kampe_telegram_2fa import FrozenClock, MemoryCodeStore, MemoryIdentityStore

clock = FrozenClock()
tfa = TelegramTwoFactor(
    config=config,
    store=MemoryCodeStore(clock),
    identities=MemoryIdentityStore(clock),
    telegram=fake_client,          # record what it was asked to send
    messages=DefaultMessages(),
    clock=clock,
)

tfa.push("user-1")
clock.advance(301)
# → expired, with no waiting
```

Because the library never returns the code, read it back out of the message
your fake captured — which is also a neat proof that it is not leaking
anywhere else.

---

## Tests

```bash
cd packages/python
PYTHONPATH=src python -m unittest discover -s . -t .
```

101 tests, standard library only — no pytest, no install step. They include:

- the cross-language fixtures in `/conformance`, which the PHP and Node
  packages read too, so a field name drifting here fails their suites
- `test_concurrency.py` — **real threads** against the shipped stores, released
  together through a `threading.Barrier`. This port can do what neither sibling
  can: PHP has no threads in a request and Node has one event loop, so both
  interleave by hand.
- a `YieldingClock` that forces the interleaving. Without it this suite passed
  against a store with no lock at all — CPython switches threads every few
  milliseconds and a critical section this short normally completes inside one
  slice, so the threaded tests gave false confidence until the yield was added.

Every protection has been checked by removing it and confirming the matching
test fails: the store lock, the conditional transition, the generation check on
acceptance, the proven-generation rule, and the conditional delivery cleanup.
