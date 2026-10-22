# Setting up the bot

Fifteen minutes, start to finish. Everything here is done once per environment —
and you want a *separate bot per environment*, because a webhook is registered
per bot token and staging pointing at production's bot will quietly steal its
updates.

---

## 1. Create the bot

Message [@BotFather](https://t.me/BotFather):

```
/newbot
```

It asks for a display name (anything) and a username (must end in `bot`). It then
gives you a token that looks like `123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw`.

**That token is a credential.** It can read every message sent to your bot and
send messages as it. Treat it exactly like a database password: environment
variable only, never committed, rotated through `/revoke` if it ever leaks.

While you are there, two optional settings worth doing:

```
/setdescription     — shown before a user starts the bot
/setcommands        — makes the commands discoverable in the client UI
```

For `/setcommands`, paste:

```
code - Get a verification code
status - Check whether this chat is linked
help - What this bot does
```

Leave `/setjoingroups` **disabled**. This bot has no business in a group, and the
handler refuses to serve non-private chats anyway.

---

## 2. Generate a webhook secret

This is the value Telegram will send back in a header on every update, and it is
what makes the webhook authenticated rather than open to the world. See
[SPEC.md section 7](../SPEC.md#7-webhook-security) for what skipping it costs you.

PHP:

```bash
php artisan telegram:webhook --generate-secret
```

Node, or anywhere:

```bash
node -e "console.log(require('crypto').randomBytes(36).toString('base64url'))"
```

It must be 32 to 256 characters of `A-Za-z0-9_-`. Both packages refuse to start
with anything shorter.

---

## 3. Configure the application

```dotenv
TELEGRAM_BOT_TOKEN=123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw
TELEGRAM_BOT_USERNAME=your_bot
TELEGRAM_WEBHOOK_SECRET=<from step 2>
TELEGRAM_2FA_HASH_PEPPER=<any long random string>
```

`TELEGRAM_BOT_USERNAME` has no `@` and is what deeplinks are built from. Without
it, linking falls back to the paste flow.

The pepper means a dumped cache of code hashes cannot be matched against a
precomputed table — and for six-digit codes that table takes seconds to build, so
this is worth setting. Changing it later invalidates codes in flight, which is
harmless.

---

## 4. Register the webhook

Telegram only delivers to **HTTPS** with a certificate it trusts. There is no
exception for localhost.

PHP:

```bash
php artisan telegram:webhook
php artisan telegram:status     # confirms the token, username and settings
```

Anywhere, directly:

```bash
curl -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
  -d "url=https://example.com/telegram/webhook" \
  -d "secret_token=$TELEGRAM_WEBHOOK_SECRET" \
  -d 'allowed_updates=["message","callback_query"]' \
  -d "drop_pending_updates=true"
```

`drop_pending_updates=true` matters on a first deploy: Telegram queues updates
while no webhook is set, and you do not want a week-old `/code` replayed into a
live flow the moment you go live.

To check what Telegram thinks the state is:

```bash
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getWebhookInfo"
```

`last_error_message` in that response is the first place to look when updates
stop arriving. `has_custom_certificate`, `pending_update_count` and
`ip_address` are the other useful fields.

---

## 5. Local development

Telegram cannot reach `localhost`, so expose it:

```bash
cloudflared tunnel --url http://localhost:8000
# or: ngrok http 8000
```

Then register that URL:

```bash
php artisan telegram:webhook --url=https://your-tunnel.trycloudflare.com/telegram/webhook
```

Use a **second bot** for this. If you point your tunnel at the production bot,
production stops receiving updates the moment you register — a webhook is one per
token, last writer wins, with no warning.

When you are done:

```bash
php artisan telegram:webhook --delete
```

### Testing without Telegram at all

You do not need a tunnel to exercise the logic. Both packages ship in-memory
stores and a fake client; the test suites use nothing else. To hand your own
webhook a synthetic update:

```bash
curl -X POST http://localhost:8000/telegram/webhook \
  -H "Content-Type: application/json" \
  -H "X-Telegram-Bot-Api-Secret-Token: $TELEGRAM_WEBHOOK_SECRET" \
  -d '{"update_id":1,"message":{"message_id":1,"text":"/code","chat":{"id":"123456","type":"private"}}}'
```

Omit the header and you should get a 403. If you get anything else, stop and fix
that before going further — it means the webhook is accepting forged updates.

---

## 6. Verify the installation

- [ ] `getWebhookInfo` shows your URL and no `last_error_message`.
- [ ] A request to the webhook *without* the secret header returns 403.
- [ ] `/start` in the bot gets a reply.
- [ ] A deeplink from your settings page links the account, and a second tap on
      the same link does not.
- [ ] `/code` in a linked chat delivers a code, and a second `/code` immediately
      after is refused with a wait message.
- [ ] That code verifies on your site once, and the same code fails the second
      time.
- [ ] Five wrong guesses kill the code.
- [ ] `grep` your logs for the code you just used. There should be no hit.

---

## Troubleshooting

**No updates arriving.** Check `getWebhookInfo` for `last_error_message`. The
usual causes are a certificate Telegram does not trust, a redirect (Telegram does
not follow them, and a redirect would strip the secret header anyway), or a
middleware returning a non-200 before your handler runs.

**403 on every update.** The registered secret and the configured secret differ.
Re-register; the value Telegram holds is whatever was last sent to `setWebhook`.

**Updates arrive, nothing happens.** Confirm the chat type is `private`, and that
`allowed_updates` includes `message`.

**A code is rejected immediately after it was delivered.** Almost always a cache
store that is not shared between processes — `array` or `file`. Switch to Redis,
Memcached or a database store.

**Verification works in the bot but not in the app, or the other way round.** The
two challenge directions are writing different store keys. See
[SPEC.md section 4](../SPEC.md#4-challenge).
