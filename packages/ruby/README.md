# kampe-telegram_2fa

Telegram as a second authentication factor for Ruby 3.1+. No gem dependencies,
no framework assumptions.

Implements [SPEC.md](../../SPEC.md) v1.0, the same protocol as the
[PHP](../php) and [Node](../node) packages in this repository, so all of them
interoperate against one bot and one store.

```bash
gem install kampe-telegram_2fa
```

---

## Wiring

```ruby
require "kampe/telegram_two_factor"

include Kampe::TelegramTwoFactor   # or qualify each constant

config = Config.from_env           # or Config.new(bot_token: ..., ...)

tfa = Service.new(
  config: config,
  store: Stores::Redis.new(redis),  # or Stores::Memory for tests
  identities: MyIdentityStore.new,  # 3 methods - the only adapter you write
  telegram: TelegramClient.new(config.bot_token),
  messages: DefaultMessages.new
)
```

`Config` validates on construction and raises `ConfigurationError` rather than
accepting something that cannot be secure: a missing webhook secret, an
unlimited attempt budget, a code lifetime measured in days.

`Config.from_env` reads `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`,
`TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_2FA_HASH_PEPPER` and the optional
`TELEGRAM_2FA_CODE_TTL`, `_COOLDOWN`, `_MAX_ATTEMPTS`, `_APP_NAME`. Numbers are
parsed with `Integer(value, 10)`, not `to_i`, so `MAX_ATTEMPTS="5 attempts"` is
a startup failure rather than a silently wrong security parameter — and
`"nonsense".to_i` is `0`, which would be worse.

`TELEGRAM_2FA_HASH_PEPPER` is required and must be at least 32 characters: it is
the HMAC key for code hashes, and a six-digit code has only a million possible
values, so an unkeyed digest of one is reversed by a table anyone can build in
seconds.

### The identity store

Three methods over your own users table. In ActiveRecord:

```ruby
class UserIdentityStore
  include Kampe::TelegramTwoFactor

  def find_by_user_id(user_id)
    to_identity(User.find_by(id: user_id))
  end

  def find_by_chat_id(chat_id)
    to_identity(User.find_by(telegram_chat_id: chat_id))
  end

  # The comparison is part of the write. Validating in application code and
  # then writing leaves a window in which a recovery can land and be silently
  # overwritten - which is how a replacement token outlives the enrollment it
  # proved.
  def transition(user_id, chat_id, expected, next_generation)
    scope = User.where(id: user_id)
    scope = scope.where(telegram_enrollment: expected) unless expected == ANY_GENERATION

    updated = scope.update_all(
      telegram_chat_id: chat_id,
      telegram_linked_at: chat_id.nil? ? nil : Time.now,
      telegram_enrollment: next_generation
    )

    # Changed under us: nothing was written, and the caller decides whether
    # that is a conflict or a stale token.
    return nil unless updated == 1

    find_by_user_id(user_id)
  rescue ActiveRecord::RecordNotUnique
    # The unique index on telegram_chat_id is what actually guarantees one chat
    # per account: two concurrent transitions both pass an application check,
    # and only one can pass the index.
    raise ChatAlreadyLinked, "That chat is already a second factor."
  end

  private

  def to_identity(user)
    return nil if user.nil?

    # Returned even when no chat is linked: the generation outlives the
    # binding, so a token minted before an unlink stays void after a relink.
    Identity.new(
      user_id: user.id.to_s,
      chat_id: user.telegram_chat_id,
      linked_at: user.telegram_linked_at&.to_i,
      generation: user.telegram_enrollment
    )
  end
end
```

The matching migration:

```ruby
add_column :users, :telegram_chat_id, :string
add_column :users, :telegram_linked_at, :datetime
add_column :users, :telegram_enrollment, :string   # kept when unlinked, on purpose

add_index :users, :telegram_chat_id, unique: true  # load-bearing
```

### The webhook

```ruby
verifier = Webhook::Verifier.new(config)
handler = Webhook::Handler.new(
  service: tfa, config: config, store: store,
  telegram: telegram, messages: messages
)

post "/telegram/webhook" do
  halt 403 unless verifier.accepts?(request.env["HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN"],
                                    request.ip)

  begin
    handler.handle(JSON.parse(request.body.read))
  rescue StandardError => e
    # The failure, never the payload: the payload contains the codes.
    logger.error("telegram-2fa: handler failed: #{e.class}")
  end

  content_type :json
  { ok: true }.to_json   # always 200 - see SPEC.md 7.5
end
```

The header name is `Webhook::SECRET_HEADER`. Skipping the verifier makes the
endpoint accept "this chat id is asking for a code" from anyone who finds the
URL — see [SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

Adding your own commands:

```ruby
handler.on("balance") do |chat_id, _argument|
  telegram.send_message(chat_id, "Balance: #{balance_for(chat_id)}")
end
```

---

## API

### Linking

| Method | Purpose |
| --- | --- |
| `start_deep_link(user_id)` | Mint a nonce bound to the account; `.url` is the `t.me` link. |
| `complete_deep_link(token, chat_id)` | Resolve a `/start` payload. Single use. |
| `start_paste_link(chat_id)` | Bot side: mint an 8-character code bound to the chat. |
| `complete_paste_link(user_id, code)` | Authenticated page side. Rate-limit this. |
| `start_chat_replacement(user_id, code)` | Move to a new Telegram account, proving the old one first. Returns a `LinkRequest` on success, a failed `VerificationResult` otherwise. |

### Challenge and verification

| Method | Purpose |
| --- | --- |
| `push(user_id, purpose = PURPOSE_LOGIN)` | Issue a code and send it. |
| `pull(chat_id)` | The user asked the bot for one; purpose `on_demand`. |
| `verify(user_id, code, purpose = PURPOSE_LOGIN)` | Check a code. |

Neither challenge method returns the code, so both results are safe to render
into a response.

`purpose` names the step a code authorises and is checked on every
verification:

```ruby
tfa.push(user.id, "withdrawal")
# ...
tfa.verify(user.id, code, "withdrawal")   # a login code will not pass
```

There is no "match anything" value, and the default is `login` on both sides
rather than a wildcard. Constants: `PURPOSE_LOGIN`, `PURPOSE_ON_DEMAND`,
`PURPOSE_REPLACE`, `PURPOSE_UNLINK`. A code the user fetched with `/code`
carries `on_demand` and satisfies any purpose, which is what keeps `/code`
usable for confirming an unlink; narrow that with `on_demand_satisfies:`.

### State and removal

| Method | Purpose |
| --- | --- |
| `linked?(user_id)` | Verified link present. |
| `identity(user_id)` / `identity_for_chat(chat_id)` | The binding, either direction. |
| `unlink(user_id, code)` | Remove, with proof under purpose `unlink`. |
| `unlink_after_external_proof(user_id, reason)` | Remove, when another factor proved it. |

`result.error` on a failure is one of the protocol's shared strings
(`ErrorCode::NOT_LINKED`, `COOLDOWN`, `INVALID`, …), and
`ErrorCode.message(result.error)` gives text safe to show a user. Every result
also answers `to_h`, which never contains the code.

---

## What the gem gives you

| Constant | What it is |
| --- | --- |
| `Service` | The protocol. |
| `Config` | Validated configuration, plus `from_env` and `generate_secret`. |
| `Stores::Memory`, `Stores::MemoryIdentities` | In-process, for tests. |
| `Stores::Redis` | Needs `get`, `set(key, value, ex:, nx:)`, `del` and either `getdel` or `eval` — redis-rb 4.6+ as it is. |
| `TelegramClient` | Telegram over `net/http`. |
| `DefaultMessages`, `escape_html` | Bot copy, and the escaper to use if you write your own. |
| `Webhook::Verifier`, `Webhook::SECRET_HEADER`, `Webhook::TELEGRAM_RANGES` | Webhook authentication. |
| `Webhook::Handler` | Command dispatch. |
| `ErrorCode` |  The shared error vocabulary, plus user-facing text. |
| `CodeGenerator`, `CodeHasher` | CSPRNG codes; HMAC plus `OpenSSL.secure_compare`. |
| `SystemClock`, `FrozenClock` | A clock you control, for testing expiry without sleeping. |
| `Identity`, `ANY_GENERATION` | The binding, and the "skip the comparison" sentinel. |

A command-style client such as redis-client, which speaks only `call`, needs a
wrapper:

```ruby
class RedisClientAdapter
  def initialize(client) = @client = client

  def get(key) = @client.call("GET", key)
  def del(key) = @client.call("DEL", key)
  def getdel(key) = @client.call("GETDEL", key)

  def set(key, value, ex: nil, nx: false)
    args = ["SET", key, value]
    args.push("EX", ex) if ex
    args.push("NX") if nx
    @client.call(*args)
  end
end
```

---

## Testing against it

```ruby
clock = FrozenClock.new

tfa = Service.new(
  config: config,
  store: Stores::Memory.new(clock),
  identities: Stores::MemoryIdentities.new(clock),
  telegram: fake_client,          # record what it was asked to send
  messages: DefaultMessages.new,
  clock: clock
)

tfa.push("user-1")
clock.advance(301)
# -> expired, with no waiting
```

Because the library never returns the code, read it back out of the message your
fake captured — which is also a neat proof that it is not leaking anywhere else.

---

### Why the code store has five methods

`take` and `add` are not a convenience. Single use and the attempt budget are
read-modify-write sequences, so built from get-check-delete they race: two
verifications arriving together both read the live record, both match, and both
succeed, while the attempt counter loses increments to the same lost update.

`take` is an atomic get-and-delete (Redis `GETDEL`, or `EVAL` on older servers);
`add` is an atomic set-if-absent that reports whether it stored, which makes the
cooldown and the webhook's idempotency claim a reservation exactly one caller
can win.

MRI's global lock does not supply this for you. The interpreter can switch
threads between any two operations, so an unsynchronised read-modify-write in
Ruby races exactly as it does anywhere else; `Stores::Memory` holds a `Mutex`
across every mutation for that reason, and `Stores::Redis` resolves its atomic
primitive at construction and raises if the client offers neither, rather than
silently racing under load.

The identity store has one mutating method, `transition`, for a related reason:
a `link`/`unlink` pair invites read-then-write, and the window between
validating a replacement token and writing the binding is where that token
outlives the enrollment it proved. Hand the store the generation you expect and
let it decide.

## Requirements

Ruby 3.1 or newer. Only the standard library: `openssl`, `securerandom`,
`net/http`, `json`, `ipaddr`.

A store with atomic get-and-delete and set-if-absent. Redis 6.2+ has `GETDEL`;
older servers are handled through `EVAL`.

## Tests

```bash
rake test
```

121 tests written clause by clause against the specification, including the
cross-language fixtures in `/conformance` that the other packages also read,
and real-thread concurrency tests against the shipped stores.

Making those race tests actually sensitive took two different devices, because
the two windows that matter are in different places:

- **Inside a critical section.** A `YieldingClock` that sleeps whenever it is
  read. Without it the store tests pass against a store with no mutex at all,
  because a critical section this short completes inside one scheduling slice —
  the false confidence a race test must not give. `concurrency_test.rb` keeps an
  explicit sensitivity check for that.
- **Between two store calls.** A clock cannot open this one: a pause inside a
  critical section is harmless, and MRI lets the thread that released a mutex
  re-acquire it before a woken waiter is scheduled, so a service built from
  get-then-delete still looks atomic. `AtomicConsumptionTest` wraps the store so
  it yields after each call returns, and asserts outright that a verification
  consumes its record in a single operation.

Each protection has been checked by removing it and confirming the matching test
fails. Two tests were found to be passing for the wrong reason that way: the
service-level single-use test did not notice an atomic `take` being split into
a read and a delete, and the "a digest must not verify against another account"
test was really being satisfied by the enrollment check, because the two
accounts in it had different generations.
