# MobileAttest

[![NuGet](https://img.shields.io/nuget/v/MobileAttest.svg)](https://www.nuget.org/packages/MobileAttest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/Freeedy/MobileAttest/blob/main/LICENSE)

Server-side verification of mobile device attestation. Apple App Attest and Android key
attestation, two mechanisms behind one result type.

```bash
dotnet add package MobileAttest
```

Targets `net8.0`. Two dependencies: BouncyCastle for cryptography and path validation,
`System.Formats.Cbor` for the Apple objects.

---

## What it answers

**At enrollment, once:** was this key created in real hardware, by this application, on a
device that booted the way it says it did.

**On every request after that:** did that same key sign these bytes.

---

## Configure once

Everything the check compares against is yours to supply. The library ships no trust root
and downloads none, so an unconfigured anchor is a rejection rather than a pass.

```csharp
var apple = new AppleAttestOptions
{
    TeamId                 = "A1B2C3D4E5",
    BundleIdAllowlist      = new[] { "com.example.app" },
    RequireProduction      = true,
    PinnedRootCertificates = PemRootStore.LoadFromPem(File.ReadAllText(appleRootPath)),
};
apple.Validate();          // empty allow list or no root throws here, not on first request

var android = new AndroidAttestOptions
{
    AllowedSignatureDigests = new[] { "44D6FB97…" },   // SHA-256 of the APK signing cert
    RequireStrongBox        = false,
    PinnedRootCertificates  = PemRootStore.LoadFromPem(File.ReadAllText(googleRootsPath)),
    RevocationPolicy        = RevocationPolicy.Skip,   // no default: you must choose
    StatusCacheTtl          = TimeSpan.FromHours(24),
};
android.Validate();
```

Google publishes **two** active roots and a deployment needs both; Apple publishes one.
Pin them by fingerprint, and refresh at deployment time rather than at runtime.

## Verify an enrollment

```csharp
var verifier = new AppleAppAttestVerifier(apple);

AttestationResult result = await verifier.VerifyAsync(
    new AppleAttestationRequest(keyId, attestationObject, challengeYouIssued),
    receivedAt);          // the instant to judge certificates at, from your own record

if (!result.IsValid)
{
    return Unauthorized();   // result.Reason names which check refused it
}

Store(result.KeyId, result.PublicKeyDer, result.AppId, result.SignCount);
```

Android is the same call with `AndroidKeyAttestationVerifier` and an
`AndroidAttestationRequest` carrying the certificate chain. Both return the same
`AttestationResult`, so one storage path serves both platforms.

## Verify what the key signs afterwards

```csharp
SignatureVerificationResult ok = DeviceSignature.Verify(
    signature:    popFromTheDevice,     // DER ECDSA, as SHA256withECDSA produces
    signedData:   nonceYouIssued,       // whatever you decided to bind
    publicKeyDer: record.PublicKeyDer); // what enrollment returned, from your store
```

Apple App Attest assertions are a CBOR envelope rather than a bare signature, and carry a
counter that must strictly advance:

```csharp
AssertionResult op = await new AppleAssertionVerifier(record.AppId).VerifyAsync(
    assertionObject, clientDataHash, record.PublicKeyDer, record.SignCount);
```

---

## What it deliberately does not do

- **No trust roots, no network of its own.** Roots, allow lists and any status endpoint are
  configuration. Where a status list is consulted, the `HttpClient` and the address come
  from you.
- **No storage.** Not a key, not a counter, not a challenge. Issuing nonces and refusing a
  second use stays with the caller — and without it, a verified signature only proves
  possession, never freshness.
- **No position it can avoid.** Whether an unverifiable key is acceptable has no default;
  a configuration that never chose is refused at startup.
- **No opinion about your protocol.** `DeviceSignature` compares bytes. Binding those bytes
  to an operation is yours; `AnchorSignatureContext` is offered for it and is optional.

Certificate validity is asked about an instant you name rather than the current clock, so a
backend can ask whether a certificate was valid when the attestation actually arrived. That
instant must come from your own record, never from the device.

---

## Documentation

- [Full usage reference](https://github.com/Freeedy/MobileAttest/blob/main/MobileAttest/README.md) — every option, every failure reason, the
  order the checks run in and why that order is itself a security property
- [Package on NuGet](https://www.nuget.org/packages/MobileAttest)

## Tests

Device vectors are deliberately not in this repository: they carry a real device key and a
real application identity. Tests locate them at run time, and a test that needs one is
skipped by name, stating the path it looked for, rather than passing quietly.

## License

[Apache-2.0](https://github.com/Freeedy/MobileAttest/blob/main/LICENSE)
