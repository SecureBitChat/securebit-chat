# Contributing

## Workflow

```bash
npm install
npm test          # 41 suites, plain node:assert, no framework
npm audit
npm run build
```

Tests are individual `.mjs` files run in sequence by `npm test`. There is no test
runner and no mocking library. A new suite is a new file, added to the `test`
script in `package.json`.

## Areas that need extra care

Changes touching any of these should come with tests that would fail without the
change:

- Verification: the safety code, the gate on control frames, protocol
  compatibility
- The Double Ratchet: key derivation, chain advance, skipped-key bounds, the
  order in which state is committed
- The inbound message path: anything that decides what reaches the interface
- ICE and TURN behaviour, and the connection recovery cycle
- File transfer consent and type policy
- IndexedDB migration
- Disconnect and resource cleanup

## Writing tests that are worth having

Two bugs reached production during recent work, and both had the same cause: the
test built its own input instead of using what the application actually produces.

One test generated its own ECDH key pairs with usages the real generator did not
grant, and passed against a build that could not establish a session at all.
Another passed a locally generated public key where the application always
supplies an imported, non-extractable one, and missed a failure that disabled
forward secrecy for one side of every conversation. Locally generated public keys
are always extractable in WebCrypto regardless of the flag you pass, so that
difference is invisible unless you look for it.

The lesson is worth stating plainly: use the real factory functions, and where a
value crosses a boundary in the application, make the test cross the same
boundary. A test that constructs its inputs verifies the algorithm. Only a test
that uses the shipped path verifies the code.

Before relying on a new test, confirm it fails when the fix is removed. A test
that cannot fail is worse than no test, because it is read as coverage.

## Documentation

When behaviour changes, update the documentation in the same commit:

| Change | Documents |
| --- | --- |
| Anything user-visible | `README.md`, `CHANGELOG.md` |
| Verification, keys, the ratchet | `doc/CRYPTOGRAPHY.md`, `doc/ARCHITECTURE.md` |
| The invitation format or the in-band key exchange | `doc/DESCRIPTOR-SBQ2.md`, `doc/CRYPTOGRAPHY.md`, `doc/ARCHITECTURE.md` |
| Deployment, ICE, file policy | `doc/CONFIGURATION.md` |
| Calls, codecs, adaptation | `doc/CALLS.md` |
| Internal interfaces | `doc/API.md` |
| Anything security relevant | `SECURITY.md` |

Values in the documentation (limits, timeouts, algorithm parameters) are taken
from the source. If you change one in code, change it in the documentation too,
otherwise the next person will trust the wrong number.

## Release notes and security fixes

Release notes describe what improved. They do not spell out how a weakness could
have been exploited, and neither do source comments. Users who have not updated
are the ones exposed by that detail, and with no server there is no way to update
everyone at once.

Comments explaining why a guard exists are valuable and should stay, because they
are what stops the guard being removed later. The distinction is between "this
check exists because completing the handshake does not prove identity" and a
reproduction recipe.

## Pull requests

Include:

- what the problem is
- what the change does
- which tests you ran, and which new ones you added
- what could regress
- for user-visible changes, a screenshot or a log
