import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import { Config } from '../src/config.js'
import { FrozenClock } from '../src/contracts.js'
import { MemoryCodeStore, MemoryIdentityStore } from '../src/stores/memory.js'
import { DefaultMessages } from '../src/telegram/messages.js'
import { TelegramTwoFactor } from '../src/telegram-two-factor.js'
import { FakeTelegramClient } from './helpers.js'

/**
 * SPEC.md section 9, against the shared fixture in /conformance.
 *
 * The README says the PHP and Node packages can run against one bot and one
 * store. That is a claim about field names and hash construction, and until
 * both suites read the same committed records it was only an assertion - this
 * package shipped camelCase field names while PHP wrote snake_case, each agreed
 * with itself, and neither could have read the other.
 *
 * The digests in the fixture are literals rather than values either
 * implementation recomputes, because a shared mistake would agree with itself.
 */
const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../conformance/records.json', import.meta.url)),
    'utf8',
  ),
) as {
  config: { key_prefix: string; hash_algorithm: string; hash_pepper: string }
  now: number
  code_record: {
    key: string
    user_id: string
    plaintext_code: string
    value: Record<string, unknown>
  }
  on_demand_record: { key: string; user_id: string; plaintext_code: string; value: unknown }
  deeplink_record: { key: string; token: string; user_id: string; value: unknown }
  paste_record: { key: string; token: string; chat_id: string; value: unknown }
  cooldown_record: { key: string; value: number }
}

function conformanceHarness() {
  const clock = new FrozenClock(fixture.now)
  const store = new MemoryCodeStore(clock)
  const identities = new MemoryIdentityStore(clock)
  const telegram = new FakeTelegramClient()

  const config = new Config({
    botToken: '123456789:AAFakeTokenForTestsOnly_0123456789abc',
    webhookSecret: 's'.repeat(48),
    botUsername: 'kampe_test_bot',
    keyPrefix: fixture.config.key_prefix,
    hashAlgorithm: fixture.config.hash_algorithm,
    hashPepper: fixture.config.hash_pepper,
  })

  const tfa = new TelegramTwoFactor({
    config,
    store,
    identities,
    telegram,
    messages: new DefaultMessages(),
    clock,
  })

  return { clock, store, identities, telegram, config, tfa }
}

describe('cross-language conformance', () => {
  it('verifies a challenge record written by the other implementation', async () => {
    const h = conformanceHarness()
    const record = fixture.code_record
    await h.identities.link(record.user_id, '555000111')

    await h.store.put(record.key, record.value, 300)

    assert.equal(
      (await h.tfa.verify(record.user_id, record.plaintext_code, 'withdrawal')).ok,
      true,
      'a record in the shared wire format must verify through the public API',
    )
  })

  it('writes a challenge record in the shared wire format', async () => {
    const h = conformanceHarness()
    await h.identities.link('user-1', '555000111')
    await h.tfa.push('user-1', 'withdrawal')

    const written = (await h.store.get(fixture.code_record.key)) as Record<string, unknown>

    assert.notEqual(written, null)
    assert.deepEqual(
      Object.keys(written),
      Object.keys(fixture.code_record.value),
      'field names and their order are the wire format of SPEC.md section 9',
    )
  })

  it('uses the key layout the specification names', async () => {
    const h = conformanceHarness()
    await h.identities.link('user-1', '555000111')
    await h.tfa.push('user-1', 'withdrawal')

    assert.notEqual(await h.store.get(fixture.code_record.key), null)
    assert.notEqual(await h.store.get(fixture.cooldown_record.key), null)
  })

  it('treats an on-demand record from elsewhere as general-purpose', async () => {
    const h = conformanceHarness()
    const record = fixture.on_demand_record
    await h.identities.link(record.user_id, '777000222')

    await h.store.put(record.key, record.value, 300)

    assert.equal((await h.tfa.verify(record.user_id, record.plaintext_code, 'login')).ok, true)
  })

  it('resolves a deeplink record written by the other implementation', async () => {
    const h = conformanceHarness()
    const record = fixture.deeplink_record

    await h.store.put(record.key, record.value, 600)

    const result = await h.tfa.completeDeepLink(record.token, '888000333')

    assert.equal(result.ok, true)
    assert.equal((await h.tfa.identity(record.user_id))?.chatId, '888000333')
  })

  it('resolves a paste record written by the other implementation', async () => {
    const h = conformanceHarness()
    const record = fixture.paste_record

    await h.store.put(record.key, record.value, 600)

    const result = await h.tfa.completePasteLink('user-9', record.token)

    assert.equal(result.ok, true)
    assert.equal((await h.tfa.identity('user-9'))?.chatId, record.chat_id)
  })

  it('writes the cooldown as a bare integer', async () => {
    const h = conformanceHarness()
    await h.identities.link('user-1', '555000111')
    await h.tfa.push('user-1')

    const written = await h.store.get(fixture.cooldown_record.key)

    // Not an object: the other implementation reads this as a number.
    assert.equal(typeof written, 'number')
    assert.equal(written, fixture.cooldown_record.value)
  })
})
