# Contributing

## Development workflow

```bash
npm install
npm test
npm audit
npm run build
```

## Security-sensitive areas

Changes involving any of the following require extra review and focused tests:

- SAS verification and protocol compatibility
- WebRTC ICE/TURN behavior
- encrypted payload validation or display sanitization
- file-transfer consent and type policy
- IndexedDB migration logic
- disconnect and resource lifecycle cleanup

## Documentation expectations

When behavior changes, update the corresponding release-facing documentation in the same change:

- `README.md`
- `SECURITY.md`
- `doc/CONFIGURATION.md`
- `doc/CRYPTOGRAPHY.md`
- `doc/SECURITY-ARCHITECTURE.md`
- `CHANGELOG.md`

## Pull requests

Please include:

- concise problem statement
- implementation summary
- tests run
- regression risks
- screenshots or logs for user-visible changes when relevant
