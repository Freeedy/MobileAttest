using MobileAttest.Abstractions;
using MobileAttest.Android;
using MobileAttest.Tests.TestSupport;

namespace MobileAttest.Tests.Android;

/// <summary>
/// Exercises the Android policy on records built field by field.
/// </summary>
/// <remarks>
/// <para>
/// Not one test here needs a device vector, and that is the reason the policy is a pure
/// function. The states worth checking -- an unlocked bootloader, a failed verified boot, an
/// imported key, a StrongBox key -- are states no vector this project holds contains. Written
/// against certificates, those paths would be untestable; written against a parsed record,
/// each is three lines.
/// </para>
/// <para>
/// Every value here is built locally. Nothing is copied out of a device vector, so nothing in
/// this file is a real package name, a real digest or a real challenge.
/// </para>
/// </remarks>
public class AndroidAttestationPolicyTests
{
    /// <summary>The challenge a record carries unless a test changes it.</summary>
    private static byte[] Challenge => Enumerable.Range(0, 32).Select(i => (byte)(i * 5)).ToArray();

    [Fact]
    public void AC10_Policy_UnlockedDeviceAndBadDigest_ReportsDeviceNotLocked()
    {
        byte[] challenge = Challenge;
        byte[] presentedDigest = Digest(0x10);
        byte[] allowedDigest = Digest(0x80);

        KeyDescriptionBuilder builder = AcceptableRecord(presentedDigest, challenge);
        builder.HardwareEnforced.RootOfTrust!.DeviceLockedContentByte = 0x00;

        AndroidAttestOptions options = OptionsAllowing(allowedDigest);

        // Two faults in one record: the bootloader is unlocked, and the signing digest is not
        // one this deployment accepts.
        AttestationFailureReason reason = AndroidAttestationPolicy.Evaluate(
            Parse(builder),
            options,
            challenge);

        // The boot state is what comes back. The application identity lives in the
        // software-enforced list, which an unlocked device controls, so a verifier that
        // reported the digest here would have read a value it had no grounds to trust yet --
        // and would have told an unlocked device which application it should have claimed to
        // be.
        Assert.Equal(AttestationFailureReason.DeviceNotLocked, reason);

        // The control that makes the assertion above mean something: the digest fault is
        // genuinely present, and it is the answer as soon as the boot fault is removed.
        KeyDescriptionBuilder locked = AcceptableRecord(presentedDigest, challenge);

        Assert.Equal(
            AttestationFailureReason.SignatureDigestNotAllowed,
            AndroidAttestationPolicy.Evaluate(Parse(locked), options, challenge));
    }

    [Fact]
    public void AC11_Policy_BootStateNotVerified_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);
        AndroidAttestOptions options = OptionsAllowing(digest);

        // Every state other than Verified, plus a value no release has defined. A device
        // whose boot chain was checked against a key its owner installed is not a device
        // whose boot chain was checked against the manufacturer's.
        foreach (long state in new long[] { 1, 2, 3, 9 })
        {
            KeyDescriptionBuilder builder = AcceptableRecord(digest, challenge);
            builder.HardwareEnforced.RootOfTrust!.VerifiedBootState = state;

            Assert.Equal(
                AttestationFailureReason.BootStateNotVerified,
                AndroidAttestationPolicy.Evaluate(Parse(builder), options, challenge));
        }

        // A record that carries no root of trust at all says nothing about verified boot, and
        // saying nothing is not the same as saying it passed.
        KeyDescriptionBuilder absent = AcceptableRecord(digest, challenge);
        absent.HardwareEnforced.RootOfTrust = null;

        Assert.Equal(
            AttestationFailureReason.BootStateNotVerified,
            AndroidAttestationPolicy.Evaluate(Parse(absent), options, challenge));
    }

    [Fact]
    public void AC11_Policy_DeviceNotLocked_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);
        AndroidAttestOptions options = OptionsAllowing(digest);

        KeyDescriptionBuilder builder = AcceptableRecord(digest, challenge);
        builder.HardwareEnforced.RootOfTrust!.DeviceLockedContentByte = 0x00;

        AttestationFailureReason reason = AndroidAttestationPolicy.Evaluate(
            Parse(builder),
            options,
            challenge);

        // A separate reason from a failed boot verification. Both are refusals, but one says
        // the owner opened the device and the other says the boot chain did not check out,
        // and whoever reads the log is going somewhere different in each case.
        Assert.Equal(AttestationFailureReason.DeviceNotLocked, reason);
        Assert.NotEqual(AttestationFailureReason.BootStateNotVerified, reason);
    }

    [Fact]
    public void AC12_Policy_ImportedKey_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);
        AndroidAttestOptions options = OptionsAllowing(digest);

        // Imported, derived, unknown -- and an origin the enumeration does not name. Only a
        // key the secure hardware generated itself was never outside it, so every other
        // answer is the same answer for this purpose.
        foreach (long origin in new long[] { 1, 2, 3, 11 })
        {
            KeyDescriptionBuilder builder = AcceptableRecord(digest, challenge);
            builder.HardwareEnforced.Origin = origin;

            Assert.Equal(
                AttestationFailureReason.KeyNotHardwareGenerated,
                AndroidAttestationPolicy.Evaluate(Parse(builder), options, challenge));
        }

        KeyDescriptionBuilder absent = AcceptableRecord(digest, challenge);
        absent.HardwareEnforced.Origin = null;

        // A record that does not state an origin does not state that the hardware generated
        // the key.
        Assert.Equal(
            AttestationFailureReason.KeyNotHardwareGenerated,
            AndroidAttestationPolicy.Evaluate(Parse(absent), options, challenge));
    }

    [Fact]
    public void AC7_Policy_RequireStrongBox_WithTeeKey_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);

        // A trusted-execution-environment key: the arrangement measured on the device this
        // project has a vector for.
        KeyDescription record = Parse(AcceptableRecord(digest, challenge));

        Assert.Equal(
            AttestationFailureReason.SecurityLevelInsufficient,
            AndroidAttestationPolicy.Evaluate(record, OptionsAllowing(digest, requireStrongBox: true), challenge));

        // The same record with the requirement lifted. Without this the test above would also
        // pass if the record were rejected for some other reason entirely.
        Assert.Equal(
            AttestationFailureReason.None,
            AndroidAttestationPolicy.Evaluate(record, OptionsAllowing(digest), challenge));
    }

    [Fact]
    public void AC7_Policy_RequireStrongBox_WithStrongBoxKey_IsAccepted()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);
        AndroidAttestOptions strict = OptionsAllowing(digest, requireStrongBox: true);

        KeyDescriptionBuilder strongBox = AcceptableRecord(digest, challenge);
        strongBox.AttestationSecurityLevel = 2;
        strongBox.KeymasterSecurityLevel = 2;

        // Synthetic, and it has to be: no StrongBox device vector exists in this project, so
        // this path is proven against a record built here and has never been measured against
        // real hardware.
        Assert.Equal(
            AttestationFailureReason.None,
            AndroidAttestationPolicy.Evaluate(Parse(strongBox), strict, challenge));

        // Both levels are read, not one. The record below claims a StrongBox attestation over
        // a key the keymaster says lives in the trusted environment; taking either field on
        // its own would accept it.
        KeyDescriptionBuilder diverging = AcceptableRecord(digest, challenge);
        diverging.AttestationSecurityLevel = 2;
        diverging.KeymasterSecurityLevel = 1;

        Assert.Equal(
            AttestationFailureReason.SecurityLevelInsufficient,
            AndroidAttestationPolicy.Evaluate(Parse(diverging), strict, challenge));

        // A software level is refused whether or not StrongBox was asked for. A record
        // produced in software can say anything, including what its hardware-enforced list
        // contains.
        KeyDescriptionBuilder software = AcceptableRecord(digest, challenge);
        software.AttestationSecurityLevel = 0;

        Assert.Equal(
            AttestationFailureReason.SecurityLevelInsufficient,
            AndroidAttestationPolicy.Evaluate(Parse(software), OptionsAllowing(digest), challenge));

        // And acceptance is membership of the two known levels, not "a number at least as
        // large as TrustedEnvironment". A device reporting a level nobody has defined would
        // pass a greater-than comparison by arithmetic alone.
        KeyDescriptionBuilder unknownLevel = AcceptableRecord(digest, challenge);
        unknownLevel.AttestationSecurityLevel = 7;
        unknownLevel.KeymasterSecurityLevel = 7;

        Assert.Equal(
            AttestationFailureReason.SecurityLevelInsufficient,
            AndroidAttestationPolicy.Evaluate(Parse(unknownLevel), strict, challenge));
    }

    [Fact]
    public void AC5_Policy_ChallengeMismatch_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);
        AndroidAttestOptions options = OptionsAllowing(digest);

        KeyDescription record = Parse(AcceptableRecord(digest, challenge));

        byte[] mutated = challenge.ToArray();
        mutated[^1] ^= 0x01;

        // One bit, at the end, where a comparison that stops early would notice last.
        Assert.Equal(
            AttestationFailureReason.ChallengeMismatch,
            AndroidAttestationPolicy.Evaluate(record, options, mutated));

        // An empty expected challenge is a rejection, not a comparison that trivially
        // succeeds. A caller who forgot to pass the challenge must not receive a valid result
        // for an attestation bound to nothing.
        Assert.Equal(
            AttestationFailureReason.ChallengeMismatch,
            AndroidAttestationPolicy.Evaluate(record, options, ReadOnlyMemory<byte>.Empty));

        // The unmutated value still passes, so the two rejections above are about the
        // challenge and not about the record.
        Assert.Equal(
            AttestationFailureReason.None,
            AndroidAttestationPolicy.Evaluate(record, options, challenge));
    }

    [Fact]
    public void AC5_Policy_ChallengeLengthMismatch_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);
        AndroidAttestOptions options = OptionsAllowing(digest);

        KeyDescription record = Parse(AcceptableRecord(digest, challenge));

        // A prefix of the real challenge. A comparison written as "the first n bytes agree"
        // would accept this, and a caller could then be talked down to a one-byte challenge.
        Assert.Equal(
            AttestationFailureReason.ChallengeMismatch,
            AndroidAttestationPolicy.Evaluate(record, options, challenge.Take(16).ToArray()));

        // And the same value with bytes appended.
        Assert.Equal(
            AttestationFailureReason.ChallengeMismatch,
            AndroidAttestationPolicy.Evaluate(record, options, challenge.Concat(new byte[] { 0x00 }).ToArray()));
    }

    [Fact]
    public void AC6_Policy_DigestNotInAllowlist_IsRejected()
    {
        byte[] challenge = Challenge;
        byte[] presented = Digest(0x10);

        KeyDescription record = Parse(AcceptableRecord(presented, challenge));

        // Another application's signing digest. Everything else about the device is in order,
        // which is exactly the case the allowlist exists for.
        Assert.Equal(
            AttestationFailureReason.SignatureDigestNotAllowed,
            AndroidAttestationPolicy.Evaluate(record, OptionsAllowing(Digest(0x80)), challenge));

        // An empty allowlist compares against nothing. It is a rejection here rather than an
        // acceptance, and AndroidAttestOptions.Validate refuses to be configured that way at
        // all.
        Assert.Equal(
            AttestationFailureReason.SignatureDigestNotAllowed,
            AndroidAttestationPolicy.Evaluate(
                record,
                new AndroidAttestOptions { AllowedSignatureDigests = Array.Empty<string>() },
                challenge));

        // An entry that is not hexadecimal cannot match anything. It narrows the allowlist
        // rather than widening it: the outcome is a refusal, never a pass.
        Assert.Equal(
            AttestationFailureReason.SignatureDigestNotAllowed,
            AndroidAttestationPolicy.Evaluate(
                record,
                new AndroidAttestOptions { AllowedSignatureDigests = new[] { "not hexadecimal" } },
                challenge));

        // A record that names no application at all has no digest to check, so there is
        // nothing on which to accept it.
        KeyDescriptionBuilder noApplication = AcceptableRecord(presented, challenge);
        noApplication.SoftwareEnforced.AttestationApplicationId = null;

        Assert.Equal(
            AttestationFailureReason.SignatureDigestNotAllowed,
            AndroidAttestationPolicy.Evaluate(Parse(noApplication), OptionsAllowing(presented), challenge));
    }

    [Fact]
    public void AC6_Policy_MultipleDigests_AnyAllowed_IsAccepted()
    {
        byte[] challenge = Challenge;
        byte[] first = Digest(0x10);
        byte[] second = Digest(0x40);

        KeyDescriptionBuilder builder = AcceptableRecord(first, challenge);
        builder.SoftwareEnforced.AttestationApplicationId = KeyDescriptionBuilder.EncodeAttestationApplicationId(
            new[] { ("com.example.policy", 1L) },
            new[] { first, second });

        KeyDescription record = Parse(builder);

        // An application signed by more than one certificate -- a signing key rotation in
        // progress -- presents every digest it has. Matching any one of them is enough, and
        // insisting on the first would reject the application on the day it rotates.
        Assert.Equal(
            AttestationFailureReason.None,
            AndroidAttestationPolicy.Evaluate(record, OptionsAllowing(second), challenge));

        // The allowlist may also hold several entries, only one of which is this application.
        AndroidAttestOptions several = new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[]
            {
                Convert.ToHexString(Digest(0x80)),
                Convert.ToHexString(first).ToLowerInvariant(),
            },
        };

        // The lower-case entry above also settles the case question: the configured text is
        // decoded to octets before anything is compared, so how the digest was written down
        // is not a reason to reject an application.
        Assert.Equal(
            AttestationFailureReason.None,
            AndroidAttestationPolicy.Evaluate(record, several, challenge));
    }

    [Fact]
    public void AC10_Policy_AllChecksPass_ReturnsNone()
    {
        byte[] challenge = Challenge;
        byte[] digest = Digest(0x10);

        // The arrangement measured on a real device: the application identity in the
        // software-enforced list, the origin and the root of trust in the hardware-enforced
        // one, a trusted execution environment rather than StrongBox.
        AttestationFailureReason reason = AndroidAttestationPolicy.Evaluate(
            Parse(AcceptableRecord(digest, challenge)),
            OptionsAllowing(digest),
            challenge);

        // A policy that only ever refuses would pass every other test in this file. This is
        // the one that says it can also accept.
        Assert.Equal(AttestationFailureReason.None, reason);
    }

    /// <summary>Builds a distinct 32-byte digest from a seed, so two of them never collide.</summary>
    private static byte[] Digest(byte seed) =>
        Enumerable.Range(0, 32).Select(i => (byte)(seed + i)).ToArray();

    /// <summary>
    /// A record every check accepts, which each test then breaks in exactly one place.
    /// </summary>
    /// <remarks>
    /// Starting from an accepted record is what makes a failing assertion informative: the
    /// reason that comes back is caused by the single field the test changed, and not by
    /// something else that was never right to begin with.
    /// </remarks>
    private static KeyDescriptionBuilder AcceptableRecord(byte[] signatureDigest, byte[] challenge)
    {
        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();
        builder.AttestationChallenge = challenge;
        builder.SoftwareEnforced.AttestationApplicationId = KeyDescriptionBuilder.EncodeAttestationApplicationId(
            new[] { ("com.example.policy", 1L) },
            new[] { signatureDigest });

        return builder;
    }

    private static AndroidAttestOptions OptionsAllowing(byte[] signatureDigest, bool requireStrongBox = false) =>
        new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[] { Convert.ToHexString(signatureDigest) },
            RequireStrongBox = requireStrongBox,
        };

    private static KeyDescription Parse(KeyDescriptionBuilder builder)
    {
        Assert.True(
            KeyDescription.TryParse(builder.Build(), out KeyDescription? parsed),
            "the builder produced a record the parser rejected, so this test is not testing the policy");

        return parsed!;
    }
}
