using MobileAttest.Abstractions;
using MobileAttest.Protocol;
using MobileAttest.Tests.TestSupport;
using Org.BouncyCastle.Crypto;

namespace MobileAttest.Tests.EndToEnd;

/// <summary>
/// The second half of what a device key proves: not "this key is real" -- attestation
/// settled that once -- but <b>"that same key signed these bytes"</b>, on every later
/// request.
/// </summary>
/// <remarks>
/// <para>
/// These tests use a key this file generates rather than a device vector, and that is the
/// right choice here rather than a compromise. The question under test is whether an ECDSA
/// signature verifies against the public key it was made with, and a synthetic key answers
/// it exactly as a Secure Enclave key would. What a real device adds -- that the key was
/// born in hardware -- is attestation's claim, and
/// <see cref="DeviceEnrollmentFlowTests"/> tests it on real material.
/// </para>
/// <para>
/// The signed bytes here are deliberately varied: a bare nonce, a long request body, a
/// domain-separated digest. The verifier treats all three identically, which is the
/// property these tests exist to hold in place -- the library must not acquire an opinion
/// about what the bytes mean.
/// </para>
/// <para><b>What these tests do not claim</b></para>
/// <para>
/// Nothing here shows that a verified signature was fresh, or that it was made for the
/// operation being performed. Those are the caller's to enforce, and the last test in this
/// file demonstrates the one tool the library offers for the second of them -- while
/// showing that the verifier itself remains indifferent.
/// </para>
/// </remarks>
public class DeviceSignatureFlowTests
{
    /// <summary>A request body of the shape a backend would actually be asked to authorise.</summary>
    private static byte[] RequestBody =>
        "{\"operation\":\"sign\",\"documentId\":\"doc-42\",\"amount\":100}"u8.ToArray();

    /// <summary>A server-issued value, as the nonce store would hand it back.</summary>
    private static byte[] Nonce =>
        Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();

    [Fact]
    public void Flow_SignedNonce_VerifiesAgainstTheStoredKey()
    {
        // ---- Enrollment stored this. Everything below reads it and nothing else.
        AsymmetricCipherKeyPair device = AssertionBuilder.GenerateKeyPair();
        byte[] storedPublicKeyDer = AssertionBuilder.PublicKeyDer(device.Public);

        // ---- The device signs what the server issued.
        byte[] signature = AssertionBuilder.Sign(device.Private, Nonce);

        SignatureVerificationResult accepted =
            DeviceSignature.Verify(signature, Nonce, storedPublicKeyDer);

        Assert.True(accepted.IsValid, $"the signature was refused with {accepted.Reason}");
        Assert.Equal(AttestationFailureReason.None, accepted.Reason);

        // ---- Control 1: a different value was signed. One byte of the nonce changes and
        // nothing else does, so the refusal names its own cause.
        byte[] otherNonce = (byte[])Nonce.Clone();
        otherNonce[^1] ^= 0xFF;

        SignatureVerificationResult wrongData =
            DeviceSignature.Verify(signature, otherNonce, storedPublicKeyDer);

        Assert.False(wrongData.IsValid, "a signature must not verify over different bytes");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, wrongData.Reason);

        // ---- Control 2: the signature itself was altered.
        byte[] tampered = (byte[])signature.Clone();
        tampered[^1] ^= 0xFF;

        SignatureVerificationResult badSignature =
            DeviceSignature.Verify(tampered, Nonce, storedPublicKeyDer);

        Assert.False(badSignature.IsValid, "an altered signature must not verify");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, badSignature.Reason);

        // ---- Control 3: another device's record. This is the one that matters most in
        // practice -- it is what stops one enrolled device from acting as another.
        byte[] strangersKey = AssertionBuilder.PublicKeyDer(AssertionBuilder.GenerateKeyPair().Public);

        SignatureVerificationResult wrongKey =
            DeviceSignature.Verify(signature, Nonce, strangersKey);

        Assert.False(wrongKey.IsValid, "a signature must not verify against another key");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, wrongKey.Reason);
    }

    [Fact]
    public void Flow_SignedRequestBody_BindsTheOperationNotOnlyTheDevice()
    {
        AsymmetricCipherKeyPair device = AssertionBuilder.GenerateKeyPair();
        byte[] storedPublicKeyDer = AssertionBuilder.PublicKeyDer(device.Public);

        // A backend that signs only a nonce learns "this device is here". Signing the
        // request as well is what turns that into "this device asked for this".
        byte[] signedData = AssertionBuilder.Sha256(RequestBody, Nonce);
        byte[] signature = AssertionBuilder.Sign(device.Private, signedData);

        Assert.True(
            DeviceSignature.Verify(signature, signedData, storedPublicKeyDer).IsValid,
            "the signed operation was refused");

        // The amount changes; the nonce and the key do not.
        byte[] tamperedBody =
            "{\"operation\":\"sign\",\"documentId\":\"doc-42\",\"amount\":900}"u8.ToArray();

        SignatureVerificationResult altered = DeviceSignature.Verify(
            signature,
            AssertionBuilder.Sha256(tamperedBody, Nonce),
            storedPublicKeyDer);

        Assert.False(altered.IsValid, "a changed request must not verify");

        // And the same request under a nonce the server issued for some other operation.
        byte[] otherNonce = Enumerable.Range(0, 32).Select(i => (byte)(255 - i)).ToArray();

        SignatureVerificationResult replayedElsewhere = DeviceSignature.Verify(
            signature,
            AssertionBuilder.Sha256(RequestBody, otherNonce),
            storedPublicKeyDer);

        Assert.False(replayedElsewhere.IsValid, "a signature must not verify under another nonce");
    }

    [Fact]
    public void Flow_AnyLengthOfSignedData_IsAccepted()
    {
        AsymmetricCipherKeyPair device = AssertionBuilder.GenerateKeyPair();
        byte[] storedPublicKeyDer = AssertionBuilder.PublicKeyDer(device.Public);

        // The caller is never forced to pre-hash: the digest is taken inside, exactly as
        // the signing side takes it. A 1-byte value and a 10 KB value are both fine, and a
        // caller that had to know which one to hash first would get it wrong eventually.
        byte[][] payloads =
        {
            new byte[] { 0x01 },
            Nonce,
            RequestBody,
            Enumerable.Range(0, 10_000).Select(i => (byte)i).ToArray(),
        };

        foreach (byte[] payload in payloads)
        {
            byte[] signature = AssertionBuilder.Sign(device.Private, payload);

            Assert.True(
                DeviceSignature.Verify(signature, payload, storedPublicKeyDer).IsValid,
                $"a {payload.Length}-byte payload was refused");
        }
    }

    [Fact]
    public void Flow_MalformedInput_IsRefusedRatherThanThrown()
    {
        AsymmetricCipherKeyPair device = AssertionBuilder.GenerateKeyPair();
        byte[] storedPublicKeyDer = AssertionBuilder.PublicKeyDer(device.Public);
        byte[] signature = AssertionBuilder.Sign(device.Private, Nonce);

        // Every one of these is something a caller can actually hold: an empty column in
        // the database, a truncated field, a record that was never populated. None of them
        // is exceptional, so none of them throws -- they are refusals.
        (string What, byte[] Signature, byte[] Key)[] cases =
        {
            ("empty signature", Array.Empty<byte>(), storedPublicKeyDer),
            ("empty key", signature, Array.Empty<byte>()),
            ("truncated key", signature, storedPublicKeyDer.AsSpan(0, 20).ToArray()),
            ("key that is not a key", signature, RequestBody),
            ("signature that is not DER", new byte[] { 1, 2, 3, 4 }, storedPublicKeyDer),
        };

        foreach ((string what, byte[] sig, byte[] key) in cases)
        {
            SignatureVerificationResult result = DeviceSignature.Verify(sig, Nonce, key);

            Assert.False(result.IsValid, $"{what}: expected a refusal");
            Assert.Equal(AttestationFailureReason.SignatureInvalid, result.Reason);
        }
    }

    [Fact]
    public void Flow_Algorithm_DefaultsToEcdsaSha256_AndAnUnsetValueIsRefused()
    {
        AsymmetricCipherKeyPair device = AssertionBuilder.GenerateKeyPair();
        byte[] storedPublicKeyDer = AssertionBuilder.PublicKeyDer(device.Public);
        byte[] signature = AssertionBuilder.Sign(device.Private, Nonce);

        // Omitted and named produce the same outcome, which is what makes the default safe
        // to leave out at a call site.
        Assert.True(DeviceSignature.Verify(signature, Nonce, storedPublicKeyDer).IsValid);

        Assert.True(
            DeviceSignature.Verify(
                signature, Nonce, storedPublicKeyDer, DeviceSignatureAlgorithm.EcdsaSha256).IsValid,
            "naming the default must be the same as omitting it");

        // A field that was never populated arrives as zero. It is refused rather than
        // treated as the default: a caller whose algorithm column is empty should learn
        // that from a failure, not carry the mistake silently for a year.
        SignatureVerificationResult unset = DeviceSignature.Verify(
            signature, Nonce, storedPublicKeyDer, default);

        Assert.False(unset.IsValid, "an unset algorithm must not fall back to the default");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, unset.Reason);

        // The same for a value outside the enumeration.
        SignatureVerificationResult unknown = DeviceSignature.Verify(
            signature, Nonce, storedPublicKeyDer, (DeviceSignatureAlgorithm)9999);

        Assert.False(unknown.IsValid, "an unknown algorithm must be refused");
    }

    [Fact]
    public void Flow_PurposeSeparation_IsTheCallersToBuild_NotTheVerifiersToEnforce()
    {
        AsymmetricCipherKeyPair device = AssertionBuilder.GenerateKeyPair();
        byte[] storedPublicKeyDer = AssertionBuilder.PublicKeyDer(device.Public);

        // The same payload, prepared for two different operations. AnchorSignatureContext
        // is offered for exactly this and is optional: the verifier never sees a purpose
        // and has no way to ask for one.
        byte[] payload = Nonce;
        byte[] forToken = AnchorSignatureContext.CreateDigest(AnchorPurpose.AuthToken, payload);
        byte[] forBinding = AnchorSignatureContext.CreateDigest(AnchorPurpose.KeyBinding, payload);

        Assert.NotEqual(forToken, forBinding);

        byte[] tokenSignature = AssertionBuilder.Sign(device.Private, forToken);

        // Against the message it was made for, it verifies.
        Assert.True(
            DeviceSignature.Verify(tokenSignature, forToken, storedPublicKeyDer).IsValid,
            "the token proof was refused");

        // Offered as proof of the other operation, it does not -- and this is the whole
        // point of the construction. Without it both messages would be the bare payload,
        // the two digests would be identical, and a proof obtained for one step would be
        // accepted as proof of the other.
        SignatureVerificationResult crossStep =
            DeviceSignature.Verify(tokenSignature, forBinding, storedPublicKeyDer);

        Assert.False(crossStep.IsValid, "a proof for one operation must not verify as another");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, crossStep.Reason);

        // The library did not do that for you. It compared bytes; the separation lives in
        // the bytes the caller chose to sign. A caller that signs the bare payload instead
        // gets a signature that verifies under either name, and nothing here would object.
        byte[] bareSignature = AssertionBuilder.Sign(device.Private, payload);

        Assert.True(
            DeviceSignature.Verify(bareSignature, payload, storedPublicKeyDer).IsValid,
            "a bare payload signature is still a valid signature -- the verifier has no opinion");
    }
}
