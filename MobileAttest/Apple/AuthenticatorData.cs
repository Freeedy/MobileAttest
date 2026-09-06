using System;
using System.Buffers.Binary;

namespace MobileAttest.Apple;

/// <summary>
/// The authenticator data structure carried inside an App Attest attestation or
/// assertion, parsed by fixed offsets against a caller-supplied shape.
/// </summary>
/// <remarks>
/// <para>The layout is:</para>
/// <code>
/// rpIdHash    32 bytes
/// flags        1 byte
/// signCount    4 bytes, big endian
/// -- attestation only --
/// aaguid              16 bytes
/// credentialIdLength   2 bytes, big endian
/// credentialId         credentialIdLength bytes
/// credentialPublicKey  the remainder
/// </code>
/// <para>
/// Every byte parsed here arrives from the device and is therefore attacker-controlled,
/// including <c>credentialIdLength</c>. The parser never slices on a declared length
/// before checking that length against the buffer it actually received, and it reports
/// malformed input by returning <see langword="false"/> rather than by throwing.
/// </para>
/// <para>
/// Which layout applies is decided by <see cref="AuthenticatorDataShape"/>, passed in by
/// the caller. It is deliberately not derived from the flags byte: a real iOS assertion
/// sets the attested-credential-data bit over a 37-byte structure that carries no
/// credential data, so treating the flag as a statement about the payload rejects genuine
/// traffic. Deriving the shape from the length instead would be worse -- a sender could
/// then pick the permissive rules by truncating its own input.
/// </para>
/// </remarks>
public sealed class AuthenticatorData
{
    /// <summary>Length in bytes of the relying-party identifier hash.</summary>
    public const int RpIdHashLength = 32;

    /// <summary>Length in bytes of the AAGUID.</summary>
    public const int AaguidLength = 16;

    /// <summary>
    /// The fixed prefix every structure begins with: hash, flags and counter. This is the
    /// smallest attestation that can be parsed, and the exact length of an assertion.
    /// </summary>
    public const int MinimumLength = RpIdHashLength + 1 + 4;

    /// <summary>Bit mask of the flag announcing that attested credential data follows.</summary>
    public const byte AttestedCredentialDataFlag = 0x40;

    /// <summary>Bit mask of the user-present flag.</summary>
    public const byte UserPresentFlag = 0x01;

    /// <summary>Bit mask of the flag announcing that extension data follows.</summary>
    public const byte ExtensionDataFlag = 0x80;

    private const int FlagsOffset = RpIdHashLength;
    private const int SignCountOffset = FlagsOffset + 1;
    private const int AaguidOffset = MinimumLength;
    private const int CredentialIdLengthOffset = AaguidOffset + AaguidLength;
    private const int CredentialIdOffset = CredentialIdLengthOffset + 2;

    private AuthenticatorData(
        AuthenticatorDataShape shape,
        ReadOnlyMemory<byte> rpIdHash,
        byte flags,
        uint signCount,
        ReadOnlyMemory<byte> aaguid,
        ReadOnlyMemory<byte> credentialId,
        ReadOnlyMemory<byte> credentialPublicKey)
    {
        Shape = shape;
        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = signCount;
        Aaguid = aaguid;
        CredentialId = credentialId;
        CredentialPublicKey = credentialPublicKey;
    }

    /// <summary>The layout this instance was parsed against.</summary>
    public AuthenticatorDataShape Shape { get; }

    /// <summary>The relying-party identifier hash, always 32 bytes.</summary>
    public ReadOnlyMemory<byte> RpIdHash { get; }

    /// <summary>The raw flags byte.</summary>
    public byte Flags { get; }

    /// <summary>The signature counter, read big endian.</summary>
    public uint SignCount { get; }

    /// <summary>
    /// The AAGUID identifying the attestation environment, or empty when no attested
    /// credential data is present.
    /// </summary>
    public ReadOnlyMemory<byte> Aaguid { get; }

    /// <summary>
    /// The credential identifier, or empty when no attested credential data is present.
    /// </summary>
    public ReadOnlyMemory<byte> CredentialId { get; }

    /// <summary>
    /// The encoded credential public key, or empty when no attested credential data is
    /// present. Any extension data that follows is included here and is separated by the
    /// caller that decodes the key.
    /// </summary>
    public ReadOnlyMemory<byte> CredentialPublicKey { get; }

    /// <summary>
    /// Whether attested credential data is actually present, meaning
    /// <see cref="Aaguid"/>, <see cref="CredentialId"/> and
    /// <see cref="CredentialPublicKey"/> hold parsed bytes.
    /// </summary>
    /// <remarks>
    /// This reports what was parsed, not what the flags byte claimed. A device assertion
    /// sets <see cref="AttestedCredentialDataFlag"/> while carrying no credential data, so
    /// a caller that read the flag directly would follow a value that is not there. The
    /// raw byte remains available on <see cref="Flags"/> for a caller that needs it.
    /// </remarks>
    public bool HasAttestedCredentialData => Shape == AuthenticatorDataShape.Attestation;

    /// <summary>Whether the user-present flag is set.</summary>
    public bool UserPresent => (Flags & UserPresentFlag) != 0;

    /// <summary>Whether the extension-data flag is set.</summary>
    public bool HasExtensionData => (Flags & ExtensionDataFlag) != 0;

    /// <summary>
    /// Parses authenticator data against the layout the caller says it is holding,
    /// rejecting anything that does not fit.
    /// </summary>
    /// <param name="data">The raw authenticator data as received from the device.</param>
    /// <param name="shape">
    /// Which message the bytes came from. The caller knows this; the bytes do not say it,
    /// and are not asked.
    /// </param>
    /// <param name="result">
    /// The parsed structure, or <see langword="null"/> when the input was rejected.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the input was fully consistent with the layout;
    /// otherwise <see langword="false"/>. This method does not throw on malformed input.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="shape"/> is not a defined value. This is a mistake in the calling
    /// code rather than bad input, so it is reported loudly instead of being folded into
    /// the <see langword="false"/> that malformed bytes produce.
    /// </exception>
    public static bool TryParse(
        ReadOnlySpan<byte> data,
        AuthenticatorDataShape shape,
        out AuthenticatorData? result)
    {
        if (shape is not (AuthenticatorDataShape.Attestation or AuthenticatorDataShape.Assertion))
        {
            throw new ArgumentOutOfRangeException(nameof(shape), shape, "Unknown authenticator data shape.");
        }

        result = null;

        if (data.Length < MinimumLength)
        {
            return false;
        }

        byte flags = data[FlagsOffset];
        uint signCount = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(SignCountOffset, 4));
        byte[] rpIdHash = data.Slice(0, RpIdHashLength).ToArray();

        if (shape == AuthenticatorDataShape.Assertion)
        {
            // An assertion is the prefix and nothing else. Measured against a real iOS
            // capture: 37 bytes, flags 0x40, no credential data behind the flag. The bit
            // is kept on Flags and is deliberately not read as a promise of a payload;
            // trailing bytes are rejected rather than ignored, so nothing can be smuggled
            // past a verifier that only looks at the fields above.
            if (data.Length != MinimumLength)
            {
                return false;
            }

            result = new AuthenticatorData(
                shape,
                rpIdHash,
                flags,
                signCount,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty);
            return true;
        }

        // Attestation. Attested credential data is what the AAGUID, credential identifier
        // and public key checks are made of, so an attestation without it is rejected
        // rather than accepted with those fields empty -- otherwise a short input would
        // skip exactly the checks it should fail.
        if ((flags & AttestedCredentialDataFlag) == 0)
        {
            return false;
        }

        // The layout promises an AAGUID and a length field. Confirm they are there before
        // reading the length that everything after it depends on.
        if (data.Length < CredentialIdOffset)
        {
            return false;
        }

        int credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(
            data.Slice(CredentialIdLengthOffset, 2));

        // The device declares this length. Checking it against the buffer is what stops a
        // declared 65535 from reading past the end, or from being allocated on trust.
        if (credentialIdLength > data.Length - CredentialIdOffset)
        {
            return false;
        }

        byte[] aaguid = data.Slice(AaguidOffset, AaguidLength).ToArray();
        byte[] credentialId = data.Slice(CredentialIdOffset, credentialIdLength).ToArray();
        byte[] credentialPublicKey = data.Slice(CredentialIdOffset + credentialIdLength).ToArray();

        result = new AuthenticatorData(
            shape,
            rpIdHash,
            flags,
            signCount,
            aaguid,
            credentialId,
            credentialPublicKey);
        return true;
    }
}
