# Contributing

Thanks for looking. This repository holds a protocol and its implementations, so
the one rule that shapes everything else is: **the specification is the source of
truth.** If an implementation and [SPEC.md](SPEC.md) disagree, that is a bug in
one of them, and which one is a decision to make deliberately.

## Reporting something

- **A vulnerability** — do not open an issue. Use a
  [private advisory](https://github.com/getkampe/telegram-2fa/security/advisories/new).
  See [SECURITY.md](SECURITY.md).
- **A bug** — say which package, which version, and the smallest reproduction you
  can manage. A failing test is the best possible bug report here.
- **An ambiguity in the specification** — open an issue against the spec rather
  than patching one implementation to match your reading. The whole value of the
  spec is that the implementations agree on it.

## Working on it

```bash
# PHP
cd packages/php && composer install && composer test

# Node
cd packages/node && npm install && npm test && npm run typecheck
```

Both suites run in well under a second and need no network, no database and no
Telegram bot — the in-memory stores and fake clients are in the packages, not
just the tests.

## What a change needs

**A test that fails before it and passes after.** The suites are organised by
specification clause, and test names read as sentences about behaviour
(`a wrong guess does not extend the codes life`). Match that.

**Parity, or a note about its absence.** A protocol change belongs in SPEC.md and
in both packages. A change to one package's framework adapter does not. If you
can only do one language, say so in the PR and open an issue for the other.

**Comments that explain why.** The code is commented at the density you see in
it: not what a line does, but why it is that way and what breaks otherwise. The
reason that matters is almost always a specific failure, so name it. "Re-store
with the remaining TTL" is less useful than "a fresh TTL here lets an attacker
keep one code alive indefinitely by guessing wrong".

**No new runtime dependencies**, unless there is no way around it. PHP requires
only `ext-curl`, and only for the bundled client; Node has none at all. Both
are easy to keep that way and hard to recover once lost.

## Style

PHP follows PSR-12 with `declare(strict_types=1)` everywhere. Node is TypeScript
in `strict` mode, two-space indent, no semicolons — match the surrounding file
and `.editorconfig` handles the rest.

Naming is parallel across languages on purpose: `startDeepLink` /
`start_deep_link`, `ErrorCode::NotLinked` / `ErrorCode.NotLinked`. A reader who
knows one package should be able to predict the other.

## The things CI will reject

Beyond the test suites, CI fails on four specific regressions, because each is
easy to reintroduce and each would quietly undo the point of the library:

- logging a raw Telegram update body — it contains the codes
- logging a code under a `code` key
- comparing code material with `==` or `===` instead of a constant-time function
- `rand`, `mt_rand` or `Math.random` anywhere in `src`

If one of these fires on something legitimate, say so in the PR rather than
working around the pattern.

## A port in a new language

Very welcome. `packages/<language>/`, and [docs/porting.md](docs/porting.md) has
the full checklist — the conformance list, the five pieces to build, and the six
places a port usually goes wrong.

## Licence

Contributions are under the [MIT licence](LICENSE), same as the rest.
