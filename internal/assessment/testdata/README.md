# Attestation verification test fixtures

`sigstore-example-bundle-provenance.json` is copied verbatim from the
[sigstore-go](https://github.com/sigstore/sigstore-go) project's own
`examples/bundle-provenance.json` (Apache License 2.0), a real GitHub
Actions-signed Sigstore attestation bundle for the `sigstore/sigstore-js`
project's `v1.3.0` npm release. Its Fulcio leaf certificate is only valid
for a short window around 2023-04-18T17:45:11Z and has long since expired
by wall-clock time; it is used here specifically to prove that verification
succeeds through the bundle's own authenticated transparency-log timestamp,
never this process's wall clock.

The embedded production trust root at `../sigstore_trusted_root.json` (used
by both production code and these tests) is likewise copied verbatim from
the same project's `examples/trusted-root-public-good.json`.

Neither file is fetched over the network during collection, replay, or
tests: both are static, build-time resources.
