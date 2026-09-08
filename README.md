# MobileAttest

Server-side verification of mobile device attestation. Two platforms, two mechanisms, one
result type.

- **Apple App Attest** — the CBOR attestation object is decoded, its certificate chain
  validated to a caller-pinned Apple root, the challenge matched against the nonce
  extension, the application identity and environment checked, the key identifier
  recomputed from the certificate Apple signed, and the counter required to start at zero.
  Assertions are then verified against the key stored at enrollment, with a counter that
  must strictly advance.
- **Android key attestation** — the chain is validated to a caller-pinned Google root, the
  attestation extension parsed into typed values, and a policy reads them in an order that
  is itself a security property: verified boot and the device lock are established before
  the application identity, because that identity lives in the software-enforced list and
  means nothing until the boot state is known.
- **Device signatures** — whatever an attested key signs afterwards is verified against the
  public key attestation returned.

```bash
dotnet add package MobileAttest
```

```csharp
AttestationResult result = await verifier.VerifyAsync(request, receivedAt);

if (result.IsValid)
{
    Store(result.KeyId, result.PublicKeyDer, result.AppId);
}
```

## What it does not do

The library is platform and application neutral, and it stays out of your protocol:

- **It ships no trust root and fetches none.** Team identifiers, bundle allow lists,
  package signature digests and trusted roots are all configuration. An unconfigured trust
  anchor is a rejection rather than a pass.
- **It reaches no network of its own.** Where a status list is consulted, the `HttpClient`
  and the address come from you.
- **It stores nothing** — not a key, not a counter, not a challenge. Nonce issuance and
  replay storage stay with the caller.
- **It takes no position it can avoid.** Whether an unverifiable key is acceptable has no
  default; a configuration that never chose is refused at startup rather than at the first
  request.

Certificate validity is asked about an instant you name rather than about the current
clock, so a backend can answer whether a certificate was valid when the attestation
actually arrived. That instant must come from your own record, never from the device.

## Documentation

Full usage, parameter by parameter, is in
[`MobileAttest/README.md`](MobileAttest/README.md).

## Dependencies

Two runtime dependencies, each pinned to an exact version: BouncyCastle for cryptography
and certificate path validation, and `System.Formats.Cbor` for the Apple objects.

## Tests

Device vectors are deliberately not part of this repository. Tests locate them at run time,
and a test that needs one is skipped by name — with the path it looked for — rather than
passing quietly.

## License

[Apache-2.0](LICENSE)
