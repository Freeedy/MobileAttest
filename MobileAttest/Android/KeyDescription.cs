using System;
using System.Formats.Asn1;
using MobileAttest.Abstractions;
using Org.BouncyCastle.X509;

namespace MobileAttest.Android;

/// <summary>
/// How strongly a claim is protected on the device.
/// </summary>
/// <remarks>
/// A device may report a value this enumeration does not name; the number is preserved
/// rather than folded into a known level, so an unrecognised level cannot be mistaken for
/// <see cref="Software"/> or for <see cref="StrongBox"/>.
/// </remarks>
public enum SecurityLevel
{
    /// <summary>Enforced by software only, with no hardware backing.</summary>
    Software = 0,

    /// <summary>Enforced by the trusted execution environment.</summary>
    TrustedEnvironment = 1,

    /// <summary>Enforced by a dedicated secure element.</summary>
    StrongBox = 2,
}

/// <summary>
/// The Android key attestation record carried by the key attestation certificate
/// extension.
/// </summary>
/// <remarks>
/// <para>
/// This type reads; it does not judge. Whether the challenge is the expected one, whether
/// the security level is high enough, whether the application is one this deployment
/// accepts -- all of that is policy, and policy belongs to the caller.
/// </para>
/// <para>
/// The bytes come from the device, which means they come from whoever holds the device.
/// Truncated input, a length that overstates the buffer, an unexpected tag class and an
/// empty input are all expected results here rather than exceptional ones, so they are
/// reported by returning <see langword="false"/>.
/// </para>
/// <code>
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER,
///     attestationSecurityLevel   ENUMERATED,
///     keymasterVersion           INTEGER,
///     keymasterSecurityLevel     ENUMERATED,
///     attestationChallenge       OCTET STRING,
///     uniqueId                   OCTET STRING,
///     softwareEnforced           AuthorizationList,
///     hardwareEnforced           AuthorizationList
/// }
/// </code>
/// <para><b>The two lists are never merged.</b></para>
/// <para>
/// <see cref="SoftwareEnforced"/> and <see cref="HardwareEnforced"/> are separate, and this
/// type offers no flattened view over them. A merged view would be convenient and would
/// destroy the only thing that makes the record worth reading: which claims the secure
/// hardware stands behind. Measured on a real device, the application identity sits in the
/// software-enforced list -- so a verifier written against a flattened view would read a
/// framework-supplied value as a hardware guarantee, and would have no way to notice.
/// </para>
/// </remarks>
public sealed class KeyDescription
{
    private KeyDescription(
        int attestationVersion,
        SecurityLevel attestationSecurityLevel,
        int keymasterVersion,
        SecurityLevel keymasterSecurityLevel,
        ReadOnlyMemory<byte> attestationChallenge,
        ReadOnlyMemory<byte> uniqueId,
        AuthorizationList softwareEnforced,
        AuthorizationList hardwareEnforced)
    {
        AttestationVersion = attestationVersion;
        AttestationSecurityLevel = attestationSecurityLevel;
        KeymasterVersion = keymasterVersion;
        KeymasterSecurityLevel = keymasterSecurityLevel;
        AttestationChallenge = attestationChallenge;
        UniqueId = uniqueId;
        SoftwareEnforced = softwareEnforced;
        HardwareEnforced = hardwareEnforced;
    }

    /// <summary>The version of the attestation record format.</summary>
    public int AttestationVersion { get; }

    /// <summary>The security level the attestation record itself was produced at.</summary>
    public SecurityLevel AttestationSecurityLevel { get; }

    /// <summary>The version of the keymaster or KeyMint implementation.</summary>
    public int KeymasterVersion { get; }

    /// <summary>The security level the keymaster or KeyMint implementation runs at.</summary>
    public SecurityLevel KeymasterSecurityLevel { get; }

    /// <summary>
    /// The challenge the caller asked the device to attest over. Comparing it with the
    /// expected challenge is the caller's decision and is not made here.
    /// </summary>
    public ReadOnlyMemory<byte> AttestationChallenge { get; }

    /// <summary>
    /// The device-unique identifier, which is empty unless the requesting application
    /// holds the privileged permission that populates it. Measured on a real device: empty.
    /// </summary>
    public ReadOnlyMemory<byte> UniqueId { get; }

    /// <summary>
    /// The list the Android framework assembled. Values here are claims the device software
    /// makes about itself.
    /// </summary>
    public AuthorizationList SoftwareEnforced { get; }

    /// <summary>
    /// The list the secure hardware enforced. Values here are what a security decision may
    /// rest on.
    /// </summary>
    public AuthorizationList HardwareEnforced { get; }

    /// <summary>
    /// Parses a KeyDescription from the octets carried by the key attestation extension.
    /// </summary>
    /// <param name="extensionOctets">
    /// The extension's octets, as received from the device.
    /// </param>
    /// <param name="result">
    /// The parsed record, or <see langword="null"/> when the input was rejected.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the input matched the structure; otherwise
    /// <see langword="false"/>. This method does not throw on malformed input.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> extensionOctets, out KeyDescription? result)
    {
        // AsnReader reads from memory, not from a span, so the bytes are copied once. The
        // input is a certificate extension of a few hundred bytes and every field read out
        // of it is copied anyway, so this is not a cost worth an unsafe lifetime.
        return TryParseCore(extensionOctets.ToArray(), out result);
    }

    /// <summary>
    /// Reads the KeyDescription out of a leaf certificate, telling an absent extension apart
    /// from an unreadable one.
    /// </summary>
    /// <param name="certificate">The leaf certificate presented by the device.</param>
    /// <param name="result">
    /// The parsed record, or <see langword="null"/> when there was nothing to parse.
    /// </param>
    /// <param name="failureReason">
    /// <see cref="AttestationFailureReason.None"/> on success,
    /// <see cref="AttestationFailureReason.AttestationExtensionMissing"/> when the
    /// certificate carries no such extension, or
    /// <see cref="AttestationFailureReason.MalformedAttestationExtension"/> when it does but
    /// the contents were rejected.
    /// </param>
    /// <returns>Whether a record was read.</returns>
    /// <remarks>
    /// The two failures are kept apart because they mean different things about the caller's
    /// deployment. A certificate with no extension is usually the wrong certificate -- an
    /// ordinary key, or the wrong element of the chain. A malformed extension is a device or
    /// an attacker sending something. Folding both into one reason would leave whoever reads
    /// the log unable to tell a configuration mistake from an attack.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="certificate"/> is <see langword="null"/>.
    /// </exception>
    public static bool TryReadFrom(
        X509Certificate certificate,
        out KeyDescription? result,
        out AttestationFailureReason failureReason)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        result = null;

        if (!AndroidOids.TryGetKeyAttestationExtension(certificate, out byte[]? extensionOctets))
        {
            failureReason = AttestationFailureReason.AttestationExtensionMissing;
            return false;
        }

        if (!TryParseCore(extensionOctets!, out result))
        {
            failureReason = AttestationFailureReason.MalformedAttestationExtension;
            return false;
        }

        failureReason = AttestationFailureReason.None;
        return true;
    }

    private static bool TryParseCore(ReadOnlyMemory<byte> extensionOctets, out KeyDescription? result)
    {
        result = null;

        // The whole parser is wrapped once, here, at the only boundary the outside world
        // enters through. AsnReader reports every encoding fault by throwing; that is the
        // right shape for a reader and the wrong shape for a caller holding device bytes,
        // and the exception text describes internals that must not reach a client.
        //
        // Nothing below recurses. Each read is at a depth the schema fixes, so a deeply
        // nested input does not walk the stack down -- it fails at the first field whose
        // type does not match, which is what makes the depth question a non-question here.
        try
        {
            AsnReader document = new AsnReader(extensionOctets, AsnEncodingRules.DER);
            AsnReader body = document.ReadSequence();

            // Trailing bytes after the record are rejected rather than ignored, so nothing
            // can ride along behind a structure that parses.
            document.ThrowIfNotEmpty();

            // Read strictly in schema order. The two version fields and the two security
            // levels are adjacent and interchangeable in type, so a parser that slipped by
            // one field would still return a record -- one describing a different device.
            if (!body.TryReadInt32(out int attestationVersion))
            {
                return false;
            }

            // An unrecognised level keeps the number the device sent; see RootOfTrust for
            // why it is not folded into a known one.
            SecurityLevel attestationSecurityLevel = body.ReadEnumeratedValue<SecurityLevel>();

            if (!body.TryReadInt32(out int keymasterVersion))
            {
                return false;
            }

            SecurityLevel keymasterSecurityLevel = body.ReadEnumeratedValue<SecurityLevel>();

            byte[] attestationChallenge = body.ReadOctetString();
            byte[] uniqueId = body.ReadOctetString();

            AsnReader softwareBody = body.ReadSequence();

            if (!AuthorizationList.TryParse(
                    softwareBody,
                    AuthorizationListSource.SoftwareEnforced,
                    out AuthorizationList? softwareEnforced))
            {
                return false;
            }

            AsnReader hardwareBody = body.ReadSequence();

            if (!AuthorizationList.TryParse(
                    hardwareBody,
                    AuthorizationListSource.HardwareEnforced,
                    out AuthorizationList? hardwareEnforced))
            {
                return false;
            }

            body.ThrowIfNotEmpty();

            result = new KeyDescription(
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced!,
                hardwareEnforced!);
            return true;
        }
        catch (AsnContentException)
        {
            result = null;
            return false;
        }
    }
}
