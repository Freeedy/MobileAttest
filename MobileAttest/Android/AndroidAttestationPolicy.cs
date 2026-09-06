using System;
using System.Collections.Generic;
using MobileAttest.Abstractions;
using MobileAttest.Internal;

namespace MobileAttest.Android;

/// <summary>
/// Decides whether a parsed Android key attestation record satisfies the caller's policy.
/// </summary>
/// <remarks>
/// <para><b>Why this is a pure function</b></para>
/// <para>
/// No certificate, no clock and no network enter here. The record is already parsed and the
/// policy is already configured, so every combination of device claims can be put in front of
/// this method directly. That matters because the states worth testing -- an unlocked
/// bootloader, a failed verified boot, an imported key -- are states no vector we hold
/// contains, and building a certificate chain for each of them would make the coverage depend
/// on material nobody has.
/// </para>
/// <para><b>The order of the checks is itself a security property</b></para>
/// <list type="number">
///   <item>verified boot, read from the hardware-enforced list</item>
///   <item>key origin, read from the hardware-enforced list</item>
///   <item>security levels</item>
///   <item>the attestation challenge</item>
///   <item>the application signing digest, read from the <b>software-enforced</b> list</item>
/// </list>
/// <para>
/// The last step is the one that has to come last. Measured on a real device, the application
/// identity sits in the software-enforced list -- the list the Android framework assembles,
/// which is the part of the device someone who has unlocked and rooted it controls. Reading it
/// is only worth anything once verified boot has been established, so the boot check runs
/// first and a device that fails it is refused for that, never for the digest. A verifier that
/// asked in the other order would let an unlocked device present itself as any application it
/// liked and would report the wrong reason while doing it.
/// </para>
/// <para><b>One reason, not a list</b></para>
/// <para>
/// Evaluation stops at the first failure. A caller receives a single
/// <see cref="AttestationFailureReason"/>, because a list of everything wrong with a device is
/// a description of that device, and descriptions of devices are what a rejection must not
/// hand back to whoever sent it.
/// </para>
/// </remarks>
public static class AndroidAttestationPolicy
{
    /// <summary>
    /// Applies the policy to one parsed record.
    /// </summary>
    /// <param name="keyDescription">The record read from the leaf certificate's extension.</param>
    /// <param name="options">The caller's policy.</param>
    /// <param name="expectedChallenge">
    /// The challenge the caller issued. An empty value is treated as a mismatch: comparing
    /// against nothing would accept whatever the device happened to send.
    /// </param>
    /// <returns>
    /// <see cref="AttestationFailureReason.None"/> when every check passed; otherwise the
    /// first check that failed.
    /// </returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    public static AttestationFailureReason Evaluate(
        KeyDescription keyDescription,
        AndroidAttestOptions options,
        ReadOnlyMemory<byte> expectedChallenge)
    {
        // Device input is answered with a reason; a null argument here is a mistake in the
        // calling code, and hiding it behind a rejection would make it look like a device
        // problem for as long as it took someone to read the log.
        if (keyDescription is null)
        {
            throw new ArgumentNullException(nameof(keyDescription));
        }

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        AttestationFailureReason bootFailure = EvaluateVerifiedBoot(keyDescription.HardwareEnforced);

        if (bootFailure != AttestationFailureReason.None)
        {
            return bootFailure;
        }

        if (keyDescription.HardwareEnforced.Origin != KeyOrigin.Generated)
        {
            // Absent as well as wrong. A record that does not say where the key came from
            // does not say the hardware generated it, and "not stated" is not "generated".
            return AttestationFailureReason.KeyNotHardwareGenerated;
        }

        AttestationFailureReason levelFailure = EvaluateSecurityLevels(keyDescription, options.RequireStrongBox);

        if (levelFailure != AttestationFailureReason.None)
        {
            return levelFailure;
        }

        if (!ChallengeMatches(keyDescription.AttestationChallenge, expectedChallenge))
        {
            return AttestationFailureReason.ChallengeMismatch;
        }

        // Only now, with the device's boot state established, is a value from the
        // software-enforced list worth reading.
        return EvaluateSignatureDigest(
            keyDescription.SoftwareEnforced.AttestationApplicationId,
            options.AllowedSignatureDigests);
    }

    /// <summary>
    /// Reads verified boot from the hardware-enforced list.
    /// </summary>
    /// <remarks>
    /// The two faults are reported separately. A device whose boot chain failed verification
    /// and a device whose bootloader is simply unlocked are different situations for whoever
    /// reads the log, and one reason covering both would lose that.
    /// </remarks>
    private static AttestationFailureReason EvaluateVerifiedBoot(AuthorizationList hardwareEnforced)
    {
        RootOfTrust? rootOfTrust = hardwareEnforced.RootOfTrust;

        if (rootOfTrust is null)
        {
            // An absent root of trust is not a device that booted cleanly and forgot to
            // mention it. Nothing here says the boot chain was verified, so nothing here may
            // be read as saying so.
            return AttestationFailureReason.BootStateNotVerified;
        }

        if (rootOfTrust.VerifiedBootState != VerifiedBootState.Verified)
        {
            return AttestationFailureReason.BootStateNotVerified;
        }

        if (!rootOfTrust.DeviceLocked)
        {
            return AttestationFailureReason.DeviceNotLocked;
        }

        return AttestationFailureReason.None;
    }

    /// <summary>
    /// Checks both security levels the record carries.
    /// </summary>
    /// <remarks>
    /// <para><b>Both, not one</b></para>
    /// <para>
    /// <c>attestationSecurityLevel</c> describes the environment that produced and signed the
    /// record; <c>keymasterSecurityLevel</c> describes the environment that holds the key.
    /// Reading only the first would accept a record where a trusted environment vouches for a
    /// key kept in software. Reading only the second would accept a software-produced record
    /// asserting that the key is in a secure element -- and a record produced in software can
    /// assert anything, including its own hardware-enforced list. Neither one alone closes
    /// both directions, so both are required to be hardware backed and, when StrongBox is
    /// demanded, both are required to be StrongBox.
    /// </para>
    /// <para><b>Membership, not a threshold</b></para>
    /// <para>
    /// The test is "is this one of the two levels we accept", not "is this at least
    /// TrustedEnvironment". The parser preserves a level number it does not recognise rather
    /// than folding it into a known one, so a device reporting an unheard-of level would pass
    /// a greater-than comparison purely by having a larger number.
    /// </para>
    /// </remarks>
    private static AttestationFailureReason EvaluateSecurityLevels(
        KeyDescription keyDescription,
        bool requireStrongBox)
    {
        if (!IsHardwareBacked(keyDescription.AttestationSecurityLevel) ||
            !IsHardwareBacked(keyDescription.KeymasterSecurityLevel))
        {
            return AttestationFailureReason.SecurityLevelInsufficient;
        }

        if (requireStrongBox &&
            (keyDescription.AttestationSecurityLevel != SecurityLevel.StrongBox ||
             keyDescription.KeymasterSecurityLevel != SecurityLevel.StrongBox))
        {
            return AttestationFailureReason.SecurityLevelInsufficient;
        }

        return AttestationFailureReason.None;
    }

    private static bool IsHardwareBacked(SecurityLevel level) =>
        level == SecurityLevel.TrustedEnvironment || level == SecurityLevel.StrongBox;

    /// <summary>
    /// Compares the attested challenge with the one the caller issued.
    /// </summary>
    /// <remarks>
    /// An empty expected challenge is a mismatch rather than a comparison that trivially
    /// succeeds. Without that, a caller who forgot to pass the challenge would receive
    /// <c>IsValid</c> for a record bound to nothing, which is the silent pass this library
    /// exists to avoid.
    /// </remarks>
    private static bool ChallengeMatches(ReadOnlyMemory<byte> presented, ReadOnlyMemory<byte> expected)
    {
        if (expected.IsEmpty)
        {
            return false;
        }

        return FixedTime.FixedTimeEquals(presented.ToArray(), expected.ToArray());
    }

    /// <summary>
    /// Checks the application signing digest against the caller's allowlist.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every configured digest is compared against every digest the device presented, and the
    /// loop does not stop at the first match: the result is accumulated so that the time taken
    /// does not depend on which entry matched. The individual comparison is
    /// <see cref="FixedTime.FixedTimeEquals"/> for the same reason.
    /// </para>
    /// <para>
    /// An absent application identity, an empty allowlist and an allowlist entry that is not
    /// valid hexadecimal all end here as a rejection. That is fail-closed in every case: a
    /// mistyped entry narrows the allowlist rather than widening it, and
    /// <see cref="AndroidAttestOptions.Validate"/> is where such an entry is reported out loud.
    /// </para>
    /// </remarks>
    private static AttestationFailureReason EvaluateSignatureDigest(
        AttestationApplicationId? applicationId,
        IReadOnlyCollection<string> allowedDigests)
    {
        if (applicationId is null || allowedDigests is null || allowedDigests.Count == 0)
        {
            return AttestationFailureReason.SignatureDigestNotAllowed;
        }

        bool matched = false;

        foreach (string allowed in allowedDigests)
        {
            if (allowed is null ||
                !AndroidAttestOptions.TryParseSignatureDigest(allowed, out byte[]? expected))
            {
                continue;
            }

            foreach (ReadOnlyMemory<byte> presented in applicationId.SignatureDigests)
            {
                // Bitwise, not logical: |= evaluates its right side every time, so the loop
                // runs to the end whether or not a match has already been found.
                matched |= FixedTime.FixedTimeEquals(expected!, presented.ToArray());
            }
        }

        return matched
            ? AttestationFailureReason.None
            : AttestationFailureReason.SignatureDigestNotAllowed;
    }
}
