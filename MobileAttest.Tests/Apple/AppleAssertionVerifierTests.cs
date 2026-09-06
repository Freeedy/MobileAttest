using MobileAttest.Abstractions;
using MobileAttest.Apple;
using MobileAttest.Tests.TestSupport;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Apple;

/// <summary>
/// Exercises the assertion path: the object, the relying-party identifier hash, the
/// signature under the stored key, and the counter.
/// </summary>
/// <remarks>
/// <para>
/// <b>The accepting path is proved on real device material.</b>
/// <see cref="AC4_RealAssertion_ValidSignature_IsAccepted"/> takes the capture's own assertion
/// object, the client data hash the capture recorded, and the public key out of the credential
/// certificate Apple signed, and the verifier accepts it. Only the Secure Enclave holding the
/// attested private key could have produced that signature, so this is an oracle nobody in
/// this repository wrote.
/// </para>
/// <para>
/// That was not always true. The signature was read as non-standard until it was measured on
/// 2026-09-06 -- twice, on two toolchains -- and found to verify under
/// <see cref="AppleAssertionDigest.NonceSignedAsMessage"/>: the nonce, signed as a message.
/// The source document's own test requirement, which expects this capture to fail the
/// signature step, is what was wrong; its step 4.2 describes the measured construction
/// correctly.
/// </para>
/// <para>
/// <b>The synthetic tests reach what one capture cannot</b> -- a counter that goes backwards, a
/// stranger's key, a wrong application identity, malformed input -- and they run on a clean
/// clone. Both kinds are pinned against the other reading of Apple's assertion step: a
/// signature over the raw concatenation must be refused, or this library would accept twice as
/// many signatures as a device can make.
/// </para>
/// <para>
/// No test in this file names an evaluation instant, and that is not an omission. Assertion
/// involves no certificate, so there is no validity window to judge and the verifier takes no
/// clock.
/// </para>
/// </remarks>
public class AppleAssertionVerifierTests
{
    private const string SignatureAlgorithm = "SHA-256withECDSA";

    // ---------------------------------------------------------------- synthetic

    [Fact]
    public async Task AC9_Assertion_SyntheticKeyValidSignature_IsAccepted()
    {
        SyntheticAssertion assertion = SyntheticAssertion.Create(signCount: 1);

        // The object this test built is one the library's own decoder reads, rather than a
        // shape only this file agrees with.
        Assert.True(
            new AppleCborReader().TryReadAssertionObject(assertion.Object, out AppleAssertionObject? decoded),
            "the synthetic assertion object did not decode");
        Assert.Equal(assertion.Signature, decoded!.Signature.ToArray());
        Assert.Equal(assertion.AuthenticatorData, decoded.AuthenticatorData.ToArray());

        AssertionResult result = await Verify(assertion);

        Assert.True(result.IsValid, $"the assertion was refused with {result.Reason}");
        Assert.Equal(AttestationFailureReason.None, result.Reason);

        // The counter the caller must store comes back, and it is the one the device sent
        // rather than a value hardcoded on the accepting path.
        Assert.Equal(1u, result.NewSignCount);

        // The identity-based constructor reaches the same hash as the stored one. A caller
        // holding the AppId from enrolment and a caller holding the hash are the same caller.
        AssertionResult viaAppId = await new AppleAssertionVerifier(assertion.AppId)
            .VerifyAsync(assertion.Object, assertion.ClientDataHash, assertion.PublicKeyDer, 0);

        Assert.True(viaAppId.IsValid, $"the identity-based constructor refused with {viaAppId.Reason}");

        IAssertionVerifier contractShape = new AppleAssertionVerifier(assertion.RpIdHash);
        Assert.Equal(Platform.Apple, contractShape.Platform);
        Assert.True((await contractShape.VerifyAsync(
            assertion.Object,
            assertion.ClientDataHash,
            assertion.PublicKeyDer,
            0)).IsValid);
    }

    [Fact]
    public async Task AC4_Assertion_SyntheticKeyWrongSignature_IsRejected()
    {
        SyntheticAssertion assertion = SyntheticAssertion.Create();

        // One byte inside the signature value. The encoding still decodes as a DER ECDSA
        // signature and is still the right length, so the rejection can only come from the
        // signature actually being checked rather than from its shape.
        byte[] tampered = (byte[])assertion.Signature.Clone();
        tampered[^1] ^= 0xFF;

        AssertionResult result = await Verify(assertion, assertionObject: assertion.ObjectWith(tampered));

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, result.Reason);

        // Bytes that are not a signature at all get the same answer and no exception. They
        // arrive inside an object a device sent, so this is ordinary input.
        AssertionResult garbage = await Verify(
            assertion,
            assertionObject: assertion.ObjectWith(new byte[] { 0x01, 0x02, 0x03 }));

        Assert.False(garbage.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, garbage.Reason);

        // And the untouched object is accepted, which is what makes both rejections
        // attributable to the signature and to nothing else about the object.
        Assert.True((await Verify(assertion)).IsValid);
    }

    [Fact]
    public async Task AC4_Assertion_SignatureFromDifferentKey_IsRejected()
    {
        SyntheticAssertion assertion = SyntheticAssertion.Create();
        AsymmetricCipherKeyPair other = AssertionBuilder.GenerateKeyPair();

        // A perfectly valid signature over exactly the right message, made by a key that was
        // never attested. This is the spoofing case: the whole security of an assertion is
        // that the signature is checked against the key stored at enrolment.
        byte[] foreignSignature = AssertionBuilder.SignAssertion(
            other.Private,
            assertion.AuthenticatorData,
            assertion.ClientDataHash);

        AssertionResult result = await Verify(
            assertion,
            assertionObject: assertion.ObjectWith(foreignSignature));

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, result.Reason);

        // The same object verified against the key that did sign it is accepted. That is what
        // makes the rejection a statement about which key was stored, rather than about the
        // signature being malformed.
        AssertionResult underItsOwnKey = await Verify(
            assertion,
            assertionObject: assertion.ObjectWith(foreignSignature),
            publicKeyDer: AssertionBuilder.PublicKeyDer(other.Public));

        Assert.True(underItsOwnKey.IsValid, $"refused with {underItsOwnKey.Reason}");

        // And the genuine signature offered against the other key is refused too, so the
        // comparison bites in both directions rather than only when the signature is foreign.
        AssertionResult swappedKey = await Verify(
            assertion,
            publicKeyDer: AssertionBuilder.PublicKeyDer(other.Public));

        Assert.False(swappedKey.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, swappedKey.Reason);
    }

    [Fact]
    public async Task AC4_Assertion_SignatureOverDifferentClientDataHash_IsRejected()
    {
        SyntheticAssertion assertion = SyntheticAssertion.Create();

        // The client data hash is what ties an assertion to one request. A signature that is
        // genuine, current and made by the attested key still must not authorise a different
        // request, so it is verified against the digest this request carries.
        byte[] anotherRequest = AssertionBuilder.Sha256(new[] { "a different request"u8.ToArray() });

        Assert.NotEqual(assertion.ClientDataHash, anotherRequest);

        AssertionResult result = await Verify(assertion, clientDataHash: anotherRequest);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, result.Reason);

        // The digest the signature was made over is accepted, so the rejection above is about
        // which request was signed and not about the digest being read at all.
        Assert.True((await Verify(assertion)).IsValid);

        // A caller that passed nothing bound the request to nothing. It is refused by the
        // signature check rather than by a special case, because that is the honest reason:
        // the device signed over a digest, and an absent one is a different message.
        AssertionResult empty = await Verify(assertion, clientDataHash: Array.Empty<byte>());

        Assert.False(empty.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, empty.Reason);
    }

    [Fact]
    public async Task AC9_Assertion_SignatureIsOverTheNonce_NotTheRawConcatenation()
    {
        // The silent-failure case this test exists for. "Verify that the signature is valid
        // for the nonce" has two readings: hand the signer the nonce, or hand it the
        // concatenation the nonce is a digest of. They differ by one hashing layer and by
        // nothing else, and picking the wrong one refuses every genuine device with a reason
        // that looks exactly like an attack -- no exception, nothing in a log.
        //
        // Which one a device actually produces was measured rather than argued; the vector
        // test in this file is that measurement.
        AsymmetricCipherKeyPair keyPair = AssertionBuilder.GenerateKeyPair();

        SyntheticAssertion overConcatenation = SyntheticAssertion.Create(
            keyPair: keyPair,
            sign: AssertionBuilder.SignOverRawConcatenation);

        AssertionResult refused = await Verify(overConcatenation);

        Assert.False(
            refused.IsValid,
            "a signature over the raw concatenation was accepted, so the verifier checks the wrong construction");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, refused.Reason);

        // The same key, the same authenticator data, the same client data hash -- signed the
        // way a device signs -- is accepted. The two differ in nothing but which value the
        // signer was handed, so this pair pins the construction exactly.
        SyntheticAssertion overNonce = SyntheticAssertion.Create(
            keyPair: keyPair,
            clientDataHash: overConcatenation.ClientDataHash);

        Assert.Equal(overConcatenation.AuthenticatorData, overNonce.AuthenticatorData);
        Assert.NotEqual(overConcatenation.Signature, overNonce.Signature);

        AssertionResult accepted = await Verify(overNonce);

        Assert.True(accepted.IsValid, $"the measured construction was refused with {accepted.Reason}");

        // Neither is accepted twice. A verifier that tried both constructions and took
        // whichever verified would pass both of these, which is the outcome this pair exists
        // to make impossible to reach unnoticed.
        Assert.False((await Verify(overConcatenation)).IsValid);
    }

    [Fact]
    public async Task AC6_Assertion_RpIdHashMismatch_IsRejectedBeforeSignatureCheck()
    {
        SyntheticAssertion assertion = SyntheticAssertion.Create();

        byte[] mutated = (byte[])assertion.RpIdHash.Clone();
        mutated[0] ^= 0xFF;

        AssertionResult result = await Verify(assertion, expectedRpIdHash: mutated);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, result.Reason);

        // The ordering, asked for directly. This input would fail the signature step too --
        // the stored key is a stranger's -- so a verifier that checked the signature first
        // would answer SignatureInvalid here. Step 1 running first is what keeps the reason
        // attributable to the step that actually failed.
        AssertionResult bothWrong = await Verify(
            assertion,
            expectedRpIdHash: mutated,
            publicKeyDer: AssertionBuilder.PublicKeyDer(AssertionBuilder.GenerateKeyPair().Public));

        Assert.False(bothWrong.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, bothWrong.Reason);

        // A different application's identity hashes to a different value, so an assertion
        // genuinely signed for one app does not verify for another.
        AssertionResult otherApp = await Verify(
            assertion,
            expectedRpIdHash: AssertionBuilder.RpIdHash("SYNTHTEAM1.com.example.other"));

        Assert.False(otherApp.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, otherApp.Reason);

        // A stored hash of the wrong length can never match, so it is refused where it is
        // configured rather than turning every device into a mismatch with no explanation.
        Assert.Throws<ArgumentException>(() => new AppleAssertionVerifier(new byte[31]));
        Assert.Throws<ArgumentException>(() => new AppleAssertionVerifier(Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => new AppleAssertionVerifier("  "));
        Assert.Throws<ArgumentNullException>(() => new AppleAssertionVerifier((string)null!));
        Assert.Throws<ArgumentNullException>(() => new AppleAssertionVerifier(assertion.RpIdHash, null!));
    }

    [Fact]
    public async Task AC8_Assertion_SignCountEqualToLast_IsRejected()
    {
        // The clone signal. A copy of the key advances its own counter independently, so the
        // same value arriving twice says two devices hold the key. Accepting equality would
        // make every replayed assertion pass.
        SyntheticAssertion assertion = SyntheticAssertion.Create(signCount: 5);

        AssertionResult repeat = await Verify(assertion, lastSignCount: 5);

        Assert.False(repeat.IsValid);
        Assert.Equal(AttestationFailureReason.SignCountNotIncreased, repeat.Reason);

        // One below is accepted, which is what makes the rejection above about equality rather
        // than about the counter being read at all.
        AssertionResult advanced = await Verify(assertion, lastSignCount: 4);

        Assert.True(advanced.IsValid, $"refused with {advanced.Reason}");
        Assert.Equal(5u, advanced.NewSignCount);
    }

    [Fact]
    public async Task AC8_Assertion_SignCountLowerThanLast_IsRejected()
    {
        // A counter that went backwards. One device cannot do this, so it is either a clone
        // whose own counter is behind or a replayed older assertion.
        SyntheticAssertion assertion = SyntheticAssertion.Create(signCount: 3);

        AssertionResult result = await Verify(assertion, lastSignCount: 9);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.SignCountNotIncreased, result.Reason);

        // Zero is never acceptable against a stored zero. Attestation carries a counter of
        // zero and the first assertion carries one -- measured on the device vector -- so a
        // caller storing zero at enrolment is already at the floor, and an assertion claiming
        // zero has not advanced.
        SyntheticAssertion neverSigned = SyntheticAssertion.Create(signCount: 0);

        AssertionResult atFloor = await Verify(neverSigned, lastSignCount: 0);

        Assert.False(atFloor.IsValid);
        Assert.Equal(AttestationFailureReason.SignCountNotIncreased, atFloor.Reason);
    }

    [Fact]
    public async Task AC8_Assertion_SignCountIncreased_IsAccepted()
    {
        // Normal traffic must not be refused by the clone check. A device's counter advances
        // by one per assertion, but nothing requires the server to have seen every one of
        // them, so a jump forward is ordinary rather than suspicious.
        AsymmetricCipherKeyPair keyPair = AssertionBuilder.GenerateKeyPair();
        uint stored = 0;

        foreach (uint counter in new uint[] { 1, 2, 7, uint.MaxValue })
        {
            SyntheticAssertion assertion = SyntheticAssertion.Create(signCount: counter, keyPair: keyPair);

            AssertionResult result = await Verify(assertion, lastSignCount: stored);

            Assert.True(result.IsValid, $"counter {counter} after {stored} was refused with {result.Reason}");
            Assert.Equal(counter, result.NewSignCount);

            stored = result.NewSignCount;
        }

        // The counter is read after the signature, never before. An assertion that names a
        // large counter but does not verify must be refused for the signature, because until
        // then the counter is a number an attacker chose.
        SyntheticAssertion advanced = SyntheticAssertion.Create(signCount: 1000, keyPair: keyPair);
        byte[] tampered = (byte[])advanced.Signature.Clone();
        tampered[^1] ^= 0xFF;

        AssertionResult unsigned = await Verify(
            advanced,
            lastSignCount: 0,
            assertionObject: advanced.ObjectWith(tampered));

        Assert.False(unsigned.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, unsigned.Reason);
    }

    [Fact]
    public async Task AC10_Assertion_MalformedInputs_ReturnResultNotException()
    {
        SyntheticAssertion assertion = SyntheticAssertion.Create();

        // Every input below is one an attacker can send or a caller can hold. None of them may
        // leave this library as an exception: a verifier that threw would hand a dispatcher a
        // way to be brought down by one malformed request.
        await Rejected(
            AttestationFailureReason.MalformedAttestationObject,
            Verify(assertion, assertionObject: Array.Empty<byte>()));

        await Rejected(
            AttestationFailureReason.MalformedAttestationObject,
            Verify(assertion, assertionObject: assertion.Object.AsSpan(0, 20).ToArray()));

        // A trailing byte after a complete object. The decoder refuses it rather than ignoring
        // it, so one input cannot have two readings.
        await Rejected(
            AttestationFailureReason.MalformedAttestationObject,
            Verify(assertion, assertionObject: CborBuilder.Concat(assertion.Object, new byte[] { 0x00 })));

        await Rejected(
            AttestationFailureReason.MalformedAttestationObject,
            Verify(assertion, assertionObject: CborBuilder.AssertionObject(null, assertion.AuthenticatorData)));

        await Rejected(
            AttestationFailureReason.MalformedAttestationObject,
            Verify(assertion, assertionObject: CborBuilder.AssertionObject(assertion.Signature, null)));

        // Authenticator data that is not exactly the 37-byte prefix. Short is a truncation;
        // long is an attempt to carry bytes no step reads.
        await Rejected(
            AttestationFailureReason.MalformedAuthenticatorData,
            Verify(assertion, assertionObject: assertion.ObjectWith(
                authenticatorData: assertion.AuthenticatorData.AsSpan(0, 36).ToArray())));

        await Rejected(
            AttestationFailureReason.MalformedAuthenticatorData,
            Verify(assertion, assertionObject: assertion.ObjectWith(
                authenticatorData: CborBuilder.Concat(assertion.AuthenticatorData, new byte[] { 0xFF }))));

        await Rejected(
            AttestationFailureReason.MalformedAuthenticatorData,
            Verify(assertion, assertionObject: assertion.ObjectWith(authenticatorData: Array.Empty<byte>())));

        // An empty signature is a signature that verifies nothing.
        await Rejected(
            AttestationFailureReason.SignatureInvalid,
            Verify(assertion, assertionObject: assertion.ObjectWith(Array.Empty<byte>())));

        // The stored key. These are the caller's own record rather than device input, and a
        // record can be truncated by a bad migration as easily as by an attacker. An
        // unreadable one fails the step it makes impossible instead of throwing.
        await Rejected(
            AttestationFailureReason.SignatureInvalid,
            Verify(assertion, publicKeyDer: Array.Empty<byte>()));

        await Rejected(
            AttestationFailureReason.SignatureInvalid,
            Verify(assertion, publicKeyDer: new byte[] { 0x30, 0x82, 0xFF, 0xFF }));

        await Rejected(
            AttestationFailureReason.SignatureInvalid,
            Verify(assertion, publicKeyDer: assertion.PublicKeyDer.AsSpan(0, 20).ToArray()));

        // A well-formed key of the wrong kind. App Attest attests a P-256 key, and an RSA key
        // reaching here was not produced by the path this library verifies.
        RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
        rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        SubjectPublicKeyInfo rsa =
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaGenerator.GenerateKeyPair().Public);

        await Rejected(
            AttestationFailureReason.SignatureInvalid,
            Verify(assertion, publicKeyDer: rsa.GetDerEncoded()));

        await Rejected(
            AttestationFailureReason.SignatureInvalid,
            Verify(assertion, clientDataHash: Array.Empty<byte>()));

        // And the untouched input still passes, so the run above is a list of rejections
        // rather than a verifier that refuses everything.
        Assert.True((await Verify(assertion)).IsValid);
    }

    // -------------------------------------------------------------------- vector

    [FixtureFact(TestVectors.AppleVectorPath)]
    public async Task AC4_RealAssertion_ValidSignature_IsAccepted()
    {
        VectorAssertion vector = VectorAssertion.Load();

        // End to end on real device material, and the only test in this project that can make
        // this claim: the assertion object a device sent, the client data hash the capture
        // recorded, and the key read out of the certificate Apple signed. Nothing here was
        // signed by this repository -- the Secure Enclave holding the attested private key is
        // the only thing that could have produced this signature.
        AssertionResult result = await vector.Verify(lastSignCount: 0);

        Assert.True(result.IsValid, $"the real device assertion was refused with {result.Reason}");
        Assert.Equal(AttestationFailureReason.None, result.Reason);

        // The counter the caller must store, measured: attestation carries zero and the first
        // assertion carries one.
        Assert.Equal(1u, result.NewSignCount);

        // Acceptance on its own would also be produced by a verifier that accepts everything,
        // so the same real material is offered back with one thing wrong at a time. Each of
        // these must be refused, and it is what turns the pass above into evidence.
        byte[] otherRequest = AssertionBuilder.Sha256(new[] { "a different request"u8.ToArray() });

        Assert.NotEqual(vector.ClientDataHash, otherRequest);

        AssertionResult wrongRequest = await vector.Verify(clientDataHash: otherRequest);

        Assert.False(wrongRequest.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, wrongRequest.Reason);

        AssertionResult strangersKey = await vector.Verify(
            publicKeyDer: AssertionBuilder.PublicKeyDer(AssertionBuilder.GenerateKeyPair().Public));

        Assert.False(strangersKey.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, strangersKey.Reason);

        byte[] tampered = (byte[])vector.Signature.Clone();
        tampered[^1] ^= 0xFF;

        AssertionResult tamperedSignature = await vector.Verify(
            assertionObject: CborBuilder.AssertionObject(tampered, vector.AuthenticatorData));

        Assert.False(tamperedSignature.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, tamperedSignature.Reason);
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC4_RealAssertion_SignatureIsOverTheNonce_NotTheRawConcatenation()
    {
        VectorAssertion vector = VectorAssertion.Load();

        // The measurement the implemented construction rests on, read independently of the
        // library so that it states what the device did rather than what the code does.
        //
        // Measured 2026-09-06 and confirmed on a second toolchain. The capture's signature
        // verifies under the attested key when the nonce is handed to the signer as a message,
        // and does not verify when the raw concatenation is. Both readings of Apple's wording
        // are tried here; exactly one holds, which is why the library implements one and
        // refuses the other rather than attempting both.
        //
        // The source document's test requirement -- that this capture must fail the signature
        // step -- is what this contradicts, and it is the requirement that was wrong: the
        // signature is genuine, because only the attested private key could have made it.
        Assert.True(
            VerifiesOver(
                vector.PublicKey,
                vector.Signature,
                AssertionBuilder.Nonce(vector.AuthenticatorData, vector.ClientDataHash)),
            "the capture no longer verifies under the measured construction, so this measurement is stale");

        Assert.False(
            VerifiesOver(vector.PublicKey, vector.Signature, vector.AuthenticatorData, vector.ClientDataHash),
            "the capture also verified over the raw concatenation, which would make the two readings equivalent");
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public async Task AC5_RealAssertion_RpIdHashIsCheckedAgainstTheStoredIdentity()
    {
        VectorAssertion vector = VectorAssertion.Load();

        // The expected hash is derived from the vector's own team and bundle identifiers, so
        // the accepting run also shows the assertion is bound to the same application the key
        // was attested for.
        Assert.True((await vector.Verify()).IsValid);

        byte[] mutated = (byte[])vector.ExpectedRpIdHash.Clone();
        mutated[0] ^= 0xFF;

        AssertionResult mismatch = await vector.Verify(expectedRpIdHash: mutated);

        Assert.False(mismatch.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, mismatch.Reason);

        // An assertion for a different application is refused, on real material rather than
        // only on invented identities.
        AssertionResult otherApp = await vector.Verify(
            expectedRpIdHash: AssertionBuilder.RpIdHash("SYNTHTEAM1.com.example.other"));

        Assert.False(otherApp.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, otherApp.Reason);

        // The hash the assertion carries is the one the enrolment carried, so the two messages
        // name the same application.
        Assert.Equal(vector.ExpectedRpIdHash, vector.AuthenticatorData.AsSpan(0, 32).ToArray());
        Assert.Equal(
            vector.AttestationAuthenticatorData.AsSpan(0, 32).ToArray(),
            vector.AuthenticatorData.AsSpan(0, 32).ToArray());
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC7_RealAssertion_ThirtySevenByteAuthData_IsParsed()
    {
        VectorAssertion vector = VectorAssertion.Load();

        // The defect T2 fixed, closed as a regression. A real assertion is 37 bytes and sets
        // the attested-credential-data flag over a payload that has none, so a parser reading
        // the flag as a promise refuses genuine traffic.
        Assert.Equal(37, vector.AuthenticatorData.Length);
        Assert.Equal(0x40, vector.AuthenticatorData[32]);

        Assert.True(
            AuthenticatorData.TryParse(
                vector.AuthenticatorData,
                AuthenticatorDataShape.Assertion,
                out AuthenticatorData? parsed),
            "the real assertion's authenticator data was rejected by the assertion shape");

        Assert.Equal(1u, parsed!.SignCount);
        Assert.Equal(AuthenticatorData.AttestedCredentialDataFlag, parsed.Flags);
        Assert.False(parsed.HasAttestedCredentialData);
        Assert.True(parsed.CredentialId.IsEmpty);

        // The shape is the caller's statement, not the bytes'. The same bytes read as an
        // attestation are refused, which is what stops a sender from choosing the permissive
        // rules by trimming its input.
        Assert.False(
            AuthenticatorData.TryParse(
                vector.AuthenticatorData,
                AuthenticatorDataShape.Attestation,
                out AuthenticatorData? asAttestation));
        Assert.Null(asAttestation);
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public async Task AC8_RealAssertion_LastSignCountEqualsOne_ReturnsSignCountNotIncreased()
    {
        VectorAssertion vector = VectorAssertion.Load();

        // The counter the device sent, measured: attestation carries zero and the first
        // assertion carries one, so the counter genuinely advances in real material.
        Assert.Equal(1u, vector.SignCount);

        // Replaying this very assertion after it was accepted once. The stored counter is now
        // its own value, so it has not advanced -- which is what a cloned key produces, and
        // what a captured assertion sent twice produces.
        AssertionResult replay = await vector.Verify(lastSignCount: 1);

        Assert.False(replay.IsValid);
        Assert.Equal(AttestationFailureReason.SignCountNotIncreased, replay.Reason);

        // A counter stored above the device's is refused too, so the comparison is an ordering
        // rather than an inequality.
        AssertionResult behind = await vector.Verify(lastSignCount: 9);

        Assert.False(behind.IsValid);
        Assert.Equal(AttestationFailureReason.SignCountNotIncreased, behind.Reason);

        // And from zero it passes, which is what makes both refusals statements about the
        // counter rather than about the assertion.
        AssertionResult first = await vector.Verify(lastSignCount: 0);

        Assert.True(first.IsValid, $"refused with {first.Reason}");
        Assert.Equal(1u, first.NewSignCount);

        // The counter is read after the signature and never before. With the signature broken
        // the answer is the signature's, even though the counter is also wrong -- until step 2
        // has run, the counter is a number the sender chose.
        byte[] tampered = (byte[])vector.Signature.Clone();
        tampered[^1] ^= 0xFF;

        AssertionResult unsigned = await vector.Verify(
            lastSignCount: 1,
            assertionObject: CborBuilder.AssertionObject(tampered, vector.AuthenticatorData));

        Assert.False(unsigned.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureInvalid, unsigned.Reason);
    }

    // ------------------------------------------------------------------ helpers

    private static Task<AssertionResult> Verify(
        SyntheticAssertion assertion,
        uint lastSignCount = 0,
        byte[]? assertionObject = null,
        byte[]? clientDataHash = null,
        byte[]? publicKeyDer = null,
        byte[]? expectedRpIdHash = null) =>
        new AppleAssertionVerifier(expectedRpIdHash ?? assertion.RpIdHash)
            .VerifyAsync(
                assertionObject ?? assertion.Object,
                clientDataHash ?? assertion.ClientDataHash,
                publicKeyDer ?? assertion.PublicKeyDer,
                lastSignCount);

    /// <summary>Asserts that a verification failed for one named reason.</summary>
    private static async Task Rejected(AttestationFailureReason expected, Task<AssertionResult> verification)
    {
        AssertionResult result = await verification;

        Assert.False(result.IsValid);
        Assert.Equal(expected, result.Reason);
        Assert.Equal(0u, result.NewSignCount);
    }

    /// <summary>
    /// Verifies a signature over the concatenation of the parts, hashed once by the signer.
    /// </summary>
    /// <remarks>
    /// Written here rather than called on the library, so the measurement it serves is an
    /// independent reading of the vector rather than a restatement of what the code did.
    /// </remarks>
    private static bool VerifiesOver(
        AsymmetricKeyParameter publicKey,
        byte[] signature,
        params byte[][] messageParts)
    {
        ISigner verifier = SignerUtilities.GetSigner(SignatureAlgorithm);
        verifier.Init(forSigning: false, publicKey);

        foreach (byte[] part in messageParts)
        {
            verifier.BlockUpdate(part, 0, part.Length);
        }

        return verifier.VerifySignature(signature);
    }

    /// <summary>
    /// The device vector's assertion, with every expected value derived from the vector.
    /// </summary>
    /// <remarks>
    /// The stored public key is read out of the credential certificate inside the
    /// <b>attestation</b> object, which is exactly what a caller would have stored at
    /// enrolment. Nothing is written down here: the team and bundle identifiers, the client
    /// data hash and the object all come from the file.
    /// </remarks>
    private sealed class VectorAssertion
    {
        private readonly AppleVectorFile _vector;

        private VectorAssertion(AppleVectorFile vector, X509Certificate credentialCertificate)
        {
            _vector = vector;
            PublicKey = credentialCertificate.GetPublicKey();
            PublicKeyDer = AssertionBuilder.PublicKeyDer(credentialCertificate);
        }

        /// <summary>The attested key, as it sits in Apple's certificate.</summary>
        public AsymmetricKeyParameter PublicKey { get; }

        /// <summary>The attested key as a caller would have stored it, DER SubjectPublicKeyInfo.</summary>
        public byte[] PublicKeyDer { get; }

        /// <summary>The assertion object as the device sent it.</summary>
        public byte[] Object => _vector.AssertionObject;

        /// <summary>The client data hash the assertion was made over.</summary>
        public byte[] ClientDataHash => _vector.AssertionClientDataHash;

        /// <summary>The authenticator data carried by the assertion object.</summary>
        public byte[] AuthenticatorData => _vector.AssertionAuthenticatorData;

        /// <summary>The authenticator data carried by the attestation object.</summary>
        public byte[] AttestationAuthenticatorData => _vector.AttestationAuthenticatorData;

        /// <summary>The signature carried by the assertion object.</summary>
        public byte[] Signature
        {
            get
            {
                Assert.True(
                    new AppleCborReader().TryReadAssertionObject(Object, out AppleAssertionObject? decoded),
                    "the vector's assertion object did not decode");

                return decoded!.Signature.ToArray();
            }
        }

        /// <summary>The counter the assertion declares.</summary>
        public uint SignCount
        {
            get
            {
                // The type and the property share a name here, so the type is spelled out.
                Assert.True(
                    MobileAttest.Apple.AuthenticatorData.TryParse(
                        AuthenticatorData,
                        AuthenticatorDataShape.Assertion,
                        out MobileAttest.Apple.AuthenticatorData? parsed));

                return parsed!.SignCount;
            }
        }

        /// <summary>The hash derived from the vector's own application identity.</summary>
        public byte[] ExpectedRpIdHash =>
            AssertionBuilder.RpIdHash($"{_vector.TeamId}.{_vector.BundleId}");

        public static VectorAssertion Load()
        {
            AppleVectorFile vector = AppleVectorFile.Load();

            Assert.True(
                new AppleCborReader().TryReadAttestationObject(
                    vector.AttestationObject,
                    out AppleAttestationObject? attestation),
                "the vector's attestation object did not decode");

            return new VectorAssertion(
                vector,
                new X509CertificateParser().ReadCertificate(attestation!.X5c[0].ToArray()));
        }

        public Task<AssertionResult> Verify(
            uint lastSignCount = 0,
            byte[]? expectedRpIdHash = null,
            byte[]? publicKeyDer = null,
            byte[]? clientDataHash = null,
            byte[]? assertionObject = null) =>
            new AppleAssertionVerifier(expectedRpIdHash ?? ExpectedRpIdHash)
                .VerifyAsync(
                    assertionObject ?? Object,
                    clientDataHash ?? ClientDataHash,
                    publicKeyDer ?? PublicKeyDer,
                    lastSignCount);
    }
}
