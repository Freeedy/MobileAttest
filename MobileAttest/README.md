# MobileAttest

A .NET class library for verifying mobile device attestation on the server.

Two platforms, two mechanisms, one result type:

- **Apple** - App Attest: a CBOR attestation object carrying an x5c chain, pinned to an
  Apple root.
- **Android** - Key Attestation: an X.509 chain pinned to a Google hardware root, with a
  KeyDescription extension.

The library is platform- and application-neutral. Team identifier, bundle identifier
allowlist, package signing digests and pinned roots are all supplied as configuration.
Nothing organisation-specific is compiled into it.

The result is an input to the calling backend's issuance or enrolment decision. The
library does not make that decision.

## Usage

### Roots are supplied by you, always

The library ships no root certificate and holds no address to fetch one from. There is no
default root and no default download location, so a root reaches the library only as
something you pass in: PEM text you load, or certificates you have already loaded into
your own trust store.

Which roots to trust is your decision. Apple's App Attest root and Google's hardware
attestation root are the usual example, and where you obtain them, how you check them and
how often you refresh them stay on your side of the boundary.

```csharp
IReadOnlyList<X509Certificate> roots = PemRootStore.LoadFromPem(pemText);
```

`LoadFromPem` throws on text it cannot parse, on anything that is not a certificate, and
on a document that yields no certificate at all. It never returns an empty list: a trust
store that comes up empty disables root pinning everywhere it is used, and nothing
downstream would report it.

### Validate your options before you verify with them

```csharp
AppleAttestOptions apple = new AppleAttestOptions
{
    TeamId = yourTeamId,
    BundleIdAllowlist = new[] { yourBundleId },
    RequireProduction = true,
    PinnedRootCertificates = roots,
};
apple.Validate();
```

`Validate()` throws on a configuration that would make verification meaningless: a missing
team identifier, an empty bundle allowlist, or an empty root list. An empty allowlist is
not "allow nothing", it is "compare against nothing", which accepts every application. An
empty root list leaves a chain pinned to nothing.

`AndroidAttestOptions` follows the same rule, over its signing digest allowlist, its pinned
roots and its revocation policy. `RequireStrongBox` defaults to `false`, because StrongBox is
absent on many devices and requiring it excludes hardware; a trusted execution environment
remains the minimum either way.

### Verify an Apple App Attest attestation

Configure the policy, hand the verifier the object the device sent, the key identifier it
reported and the challenge you issued, and say which instant to judge the certificates at.

```csharp
AppleAttestOptions apple = new AppleAttestOptions
{
    TeamId = yourTeamId,
    BundleIdAllowlist = new[] { yourBundleId },
    RequireProduction = true,
    PinnedRootCertificates = roots,
};
apple.Validate();

AppleAppAttestVerifier verifier = new AppleAppAttestVerifier(apple);

AppleAttestationRequest request = new AppleAttestationRequest(
    keyIdFromDevice,
    attestationObjectFromDevice,
    challengeYouIssued);

AttestationResult result = await verifier.VerifyAsync(request, receivedAtUtc);

if (result.IsValid)
{
    // result.KeyId        the key identifier, recomputed from Apple's certificate
    // result.PublicKeyDer the attested key, as DER SubjectPublicKeyInfo
    // result.AppId        "{TeamId}.{bundleId}", the identity that matched
    // result.Environment  Development or Production, read from the AAGUID
    // result.Receipt      the platform receipt, as received and not verified here
}
```

- `TeamId` and `BundleIdAllowlist` together form the application identities that are
  accepted. Each `"{TeamId}.{bundleId}"` is hashed and compared against the hash the device
  attested, so an empty allowlist is not "allow anything" - it is "allow nothing", and it is
  rejected with `BundleIdNotAllowed`. When no entry matches, the reason is
  `RpIdHashMismatch`: the hash covers both halves, so a wrong team and a wrong bundle are
  not distinguishable and neither is claimed.
- `RequireProduction` defaults to `true`. A development key is refused with
  `DevelopmentKeyInProduction` unless you set it to `false`. The environment is read from
  the AAGUID inside the attested authenticator data, never from anything the client says -
  there is no request field for it.
- `PinnedRootCertificates` are yours, as above. Configure none and every device is refused
  with `RootNotPinned` - the verifier has no default Apple root to fall back to. The
  intermediate is not configuration: it travels inside the attestation object's own `x5c`,
  so the root is all you supply.
- `keyIdFromDevice` is a claim, not evidence. It is compared against an identifier
  recomputed from the certificate Apple signed, and a mismatch is `KeyIdMismatch`.
- `challengeYouIssued` is what binds the attestation to this enrolment. Issuing and expiring
  challenges stays on your side; the library only compares.

#### Which instant the certificates are judged at

`receivedAtUtc` is a `DateTimeOffset` and answers "was this chain valid **then**", not "is
it valid now". Pass **your own server's record of when the attestation arrived**. Never take
it from the device, and never read it out of the attestation itself: a caller that did would
let an old attestation be replayed with the instant that makes it pass attached to it. The
library cannot check where the value came from.

This is not a freshness check. Freshness comes from the challenge, which you issue and keep
short lived; the instant only decides which certificates were inside their validity window.
An App Attest credential certificate lives about three days, so this matters in practice.

The `IAttestationVerifier` overload without an instant reads the `TimeProvider` given to the
constructor, which defaults to the system clock:

```csharp
IAttestationVerifier contractShape = new AppleAppAttestVerifier(apple, timeProvider);
AttestationResult now = await contractShape.VerifyAsync(request);
```

### Verify an Apple App Attest assertion

Attestation runs once, when a key is enrolled. An assertion runs on every request afterwards
and answers a narrower question: did the key you already attested sign *this* request?

Four things reach the verifier, and three of them are what you stored at enrolment.

```csharp
AppleAssertionVerifier verifier = new AppleAssertionVerifier(appIdFromEnrolment);

AssertionResult result = await verifier.VerifyAsync(
    assertionObjectFromDevice,
    clientDataHash,
    storedPublicKeyDer,
    storedSignCount);

if (result.IsValid)
{
    // result.NewSignCount  store this in place of storedSignCount, or clone detection stops
}
```

- `appIdFromEnrolment` is the `"{TeamId}.{bundleId}"` that `AttestationResult.AppId` gave you
  when the key was attested. The constructor hashes it once; the overload taking
  `ReadOnlyMemory<byte>` takes that 32-byte hash directly if you would rather store the hash
  than the string. Anything other than 32 bytes is rejected where you configure it, so a bad
  stored value cannot turn into an unexplained `RpIdHashMismatch` on every request.
- `clientDataHash` is `SHA256(requestBody ‖ nonce)` and you build it. Issuing the nonce,
  expiring it and computing this digest all stay on your side; the library compares and does
  not construct. Passing a digest the device did not sign over is `SignatureInvalid`, and so
  is passing an empty one.
- `storedPublicKeyDer` is the `AttestationResult.PublicKeyDer` you saved at enrolment. It is
  the only key the signature is checked against — there is no chain here, no root and no
  certificate, so nothing is pinned and nothing is fetched.
- `storedSignCount` is the counter from the last accepted assertion, or the
  `AttestationResult.SignCount` from enrolment if there has been none. The counter must
  **increase strictly**: an equal counter is refused with `SignCountNotIncreased`, because a
  cloned key advances its own copy independently and the same value arriving twice means two
  devices hold the key.

There is no evaluation instant on this call, unlike the attestation one. No certificate takes
part, so there is no validity window to judge and a date parameter would advertise a check
that does not happen.

#### What you must store, and how to key a replay cache

`NewSignCount` is only returned; this library holds no state between calls. A caller that does
not persist it compares every request against the same stale counter, which is the same as
having no clone detection.

If you keep a replay cache as well, key it on **the credential identifier and the counter**,
never on the raw bytes of the assertion object. The decoder accepts indefinite-length CBOR, so
one logical assertion can arrive under more than one byte sequence and a cache keyed on bytes
would not see the repeat.

`result.Reason` names the first check that failed. Log it; do not return it verbatim to the
device.

### Verify an Android key attestation

Configure the policy, hand the verifier the chain the device sent and the challenge you
issued, and read one result.

```csharp
AndroidAttestOptions android = new AndroidAttestOptions
{
    AllowedSignatureDigests = new[] { yourSigningCertificateDigest },
    RequireStrongBox = false,
    PinnedRootCertificates = roots,
    RevocationPolicy = RevocationPolicy.Skip,
};
android.Validate();

IAttestationVerifier verifier = new AndroidKeyAttestationVerifier(android);

AttestationRequest request = new AndroidAttestationRequest(deviceChain, challengeYouIssued);
AttestationResult result = await verifier.VerifyAsync(request);

if (result.IsValid)
{
    // result.KeyId       SHA-256 of the leaf's SubjectPublicKeyInfo
    // result.PublicKeyDer the attested key, as DER SubjectPublicKeyInfo
    // result.AppId       the package name the attestation was bound to
}
else
{
    // result.Reason names the first check that failed. Log it; do not return it verbatim
    // to the device.
}
```

- `deviceChain` is the X.509 chain as the device sent it, **leaf first**, each element DER.
- `challengeYouIssued` is the value you asked the device to attest over. Issuing and
  replaying challenges stays on your side; the library only compares. An empty challenge is
  a mismatch, not a match against nothing.
- `AllowedSignatureDigests` entries are hexadecimal, upper or lower case, no separators -
  the form `apksigner` and `keytool` print. `Validate()` rejects an entry that is not
  hexadecimal, because an entry that can never match silently shortens the allowlist.
- `RequireStrongBox` defaults to `false`. Set it only where every device you accept has a
  secure element; a trusted execution environment remains the minimum either way.
- `PinnedRootCertificates` are yours, as above. Configure none and every device is refused
  with `RootNotPinned` - the verifier has no default root to fall back to.

`Environment` is always `Unknown` for Android. There is no equivalent of Apple's
development and production AAGUIDs, and inventing one from the boot state would answer a
question the device did not answer.

Certificate validity is read against the system clock by default. Pass a `TimeProvider` to
the second constructor to read it against your own:

```csharp
IAttestationVerifier pinnedClock = new AndroidKeyAttestationVerifier(android, timeProvider);
```

#### Decide what an unverifiable key is worth

`RevocationPolicy` has no default. Leave it unset and `Validate()` refuses the configuration,
because the alternative is running whichever policy happened to be the zero value without ever
being told. There are two choices and you make one:

- `RevocationPolicy.Skip` — a key whose status could not be established is accepted, and
  verification carries on. This is the choice for a deployment that has no network access, or
  that treats revocation as advisory.
- `RevocationPolicy.HardFail` — a key whose status could not be established is refused, with
  `RevocationStatusUnavailable`.

A key the source reports as revoked or suspended is refused under **both**, with
`CertificateRevoked`. The policy decides what silence is worth; it never overrules an answer.

Nothing is looked up unless you supply a source. Without one, `NullKeyStatusSource` answers
"unknown" to everything and no network is touched — so `HardFail` with no source refuses every
verification, on the first request rather than quietly. That pairing is a mistake, and it is
meant to be an obvious one.

#### Supply the status source, the client and the address

The library creates no `HttpClient` and holds no address. Both are yours: the client's lifetime
governs socket exhaustion and DNS refresh, which belong to your application, and the address is
stated by your deployment rather than compiled in here.

```csharp
GoogleKeyStatusSource status = new GoogleKeyStatusSource(
    yourHttpClient,
    new Uri("https://android.googleapis.com/attestation/status"));   // an example address

IAttestationVerifier verifier = new AndroidKeyAttestationVerifier(
    android,
    timeProvider,
    new CachedKeyStatusSource(status, android.StatusCacheTtl, timeProvider));
```

The address above is an example of the shape, not a value the library falls back to. Configure
the one your deployment should query.

`GoogleKeyStatusSource` expects a document of this shape, and reads a serial number that is
absent from `entries` as "not listed, therefore good":

```json
{ "entries": { "1a2b3c4d": { "status": "REVOKED" } } }
```

Keys are the certificate serial number in lower-case hexadecimal, with no leading zeroes.

An unreachable host, a timed-out request, an error status code and a body that will not parse
all come back as "unknown" rather than as an exception, so a status service that is down
becomes your policy decision instead of a failed request. Cancelling the token you passed is
the exception: that is propagated, because you asked for the work to stop.

`IKeyStatusSource` is an interface. Implement it to read a list you host yourself, one you
already hold in memory, or one behind a different protocol.

#### Cache, or ask on every single request

`CachedKeyStatusSource` holds each answer for `AndroidAttestOptions.StatusCacheTtl`, which
defaults to 24 hours. Without it, every verification issues a request.

Every answer is cached for that period, "unknown" included. That is what stops an unresponsive
service from being hammered once per verification, and it has a cost worth knowing: after the
service recovers, an "unknown" that is still held stands until it expires, and under `HardFail`
that means continued refusals. So the time-to-live is also the longest a recovery can go
unnoticed. Shorten it where that matters more than the requests it saves.

Pass the same `TimeProvider` you gave the verifier, so both read one clock.

### Say which message authenticator data came from

`AuthenticatorData.TryParse` takes the layout as an argument, because the bytes do not
carry it:

```csharp
if (AuthenticatorData.TryParse(raw, AuthenticatorDataShape.Assertion, out AuthenticatorData? authData))
{
    uint counter = authData!.SignCount;
}
```

- `AuthenticatorDataShape.Attestation` requires attested credential data - the AAGUID, the
  credential identifier and the public key. Input without them is rejected rather than
  accepted with those fields empty.
- `AuthenticatorDataShape.Assertion` requires exactly the 37-byte prefix and exposes no
  attested credential data.

Pass the shape you know you are holding. A device assertion sets the
attested-credential-data flag while sending no credential data, so the flag cannot be read
as a description of the payload; and choosing the layout by length would let a sender pick
its own validation rules by truncating its input.

`TryParse` returns `false` for malformed input instead of throwing. It throws only for an
undefined shape, which is a mistake in your code rather than in the data.

### Bind a proof-of-possession signature to one operation

```csharp
byte[] digest = AnchorSignatureContext.CreateDigest(AnchorPurpose.AuthToken, payload);
```

The digest covers a protocol label and the purpose as well as the payload, so a signature
made for one operation does not verify as another. Both sides build the message the same
way; this type neither signs nor verifies.

## Dependencies

Two runtime dependencies, each pinned to an exact version:

```xml
<PackageReference Include="BouncyCastle.Cryptography" Version="[2.7.0]" />
<PackageReference Include="System.Formats.Cbor" Version="[10.0.11]" />
```

`BouncyCastle.Cryptography` is the official package. The fork `Portable.BouncyCastle` is
not a substitute for it.

`System.Formats.Cbor` decodes the App Attest attestation and assertion objects. It is not
part of the .NET 8 shared framework, so it is referenced rather than assumed. On `net8.0`
the package ships a matching assembly and declares no dependencies of its own, so neither
reference adds anything further to your closure.

Both versions are pinned in square brackets. A floating version would let the code a
verifier runs change without the change being reviewed.
