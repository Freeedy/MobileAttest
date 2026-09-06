using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace MobileAttest.Android;

/// <summary>
/// One application the attested key is bound to: its package name and version code.
/// </summary>
public sealed class AttestationPackageInfo
{
    internal AttestationPackageInfo(string packageName, long version)
    {
        PackageName = packageName;
        Version = version;
    }

    /// <summary>
    /// The package name, decoded as UTF-8.
    /// </summary>
    /// <remarks>
    /// Decoding is strict. Invalid UTF-8 is rejected as a malformed record rather than
    /// replaced with substitution characters, because a name carrying replacement
    /// characters would silently fail to match an allowlist entry while looking like a
    /// name that simply was not on the list.
    /// </remarks>
    public string PackageName { get; }

    /// <summary>The application's version code, as the device reported it.</summary>
    public long Version { get; }
}

/// <summary>
/// The application identity Android binds to an attested key.
/// </summary>
/// <remarks>
/// <para>
/// Measured on a real device (Samsung, attestation version 300): this field is carried in
/// the <b>software-enforced</b> authorisation list, not the hardware-enforced one. It is
/// assembled by the Android framework, which is exactly why it cannot be read as a
/// hardware claim -- and why a verifier that looked for it in the hardware-enforced list
/// would find nothing and reject every genuine device.
/// </para>
/// <para>
/// The structure is not a field of the authorisation list in the ordinary sense: the tag
/// carries an OCTET STRING whose octets are themselves a DER encoding, so it is parsed as
/// a document of its own.
/// </para>
/// <code>
/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos      SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
///     signatureDigests  SET OF OCTET STRING
/// }
/// </code>
/// </remarks>
public sealed class AttestationApplicationId
{
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private AttestationApplicationId(
        IReadOnlyList<AttestationPackageInfo> packageInfos,
        IReadOnlyList<ReadOnlyMemory<byte>> signatureDigests)
    {
        PackageInfos = packageInfos;
        SignatureDigests = signatureDigests;
    }

    /// <summary>The applications the key is bound to, in the order the device sent them.</summary>
    public IReadOnlyList<AttestationPackageInfo> PackageInfos { get; }

    /// <summary>
    /// The signing certificate digests of those applications, in the order the device sent
    /// them. Which digests are acceptable is configuration, decided by the caller.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> SignatureDigests { get; }

    /// <summary>
    /// Reads the nested DER document carried by the attestationApplicationId tag.
    /// </summary>
    /// <param name="encoded">The octets the tag carried.</param>
    /// <param name="result">The parsed value, or null when the document was rejected.</param>
    /// <returns>Whether the document matched the structure.</returns>
    /// <remarks>
    /// May throw <see cref="AsnContentException"/>; see
    /// <see cref="RootOfTrust.TryParse(AsnReader, out RootOfTrust?)"/> for where that is
    /// caught.
    /// </remarks>
    internal static bool TryParse(ReadOnlyMemory<byte> encoded, out AttestationApplicationId? result)
    {
        result = null;

        AsnReader document = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader body = document.ReadSequence();
        document.ThrowIfNotEmpty();

        // Element ordering inside a SET OF is not validated. Every element is read, so the
        // order carries no meaning here, and rejecting a device over the order in which it
        // listed its own digests would be a false rejection bought with no security.
        AsnReader packages = body.ReadSetOf(skipSortOrderValidation: true);
        AsnReader digests = body.ReadSetOf(skipSortOrderValidation: true);
        body.ThrowIfNotEmpty();

        List<AttestationPackageInfo> packageInfos = new List<AttestationPackageInfo>();

        while (packages.HasData)
        {
            AsnReader info = packages.ReadSequence();
            byte[] nameBytes = info.ReadOctetString();

            if (!info.TryReadInt64(out long version))
            {
                return false;
            }

            info.ThrowIfNotEmpty();

            if (!TryDecodePackageName(nameBytes, out string packageName))
            {
                return false;
            }

            packageInfos.Add(new AttestationPackageInfo(packageName, version));
        }

        List<ReadOnlyMemory<byte>> signatureDigests = new List<ReadOnlyMemory<byte>>();

        while (digests.HasData)
        {
            signatureDigests.Add(digests.ReadOctetString());
        }

        result = new AttestationApplicationId(packageInfos, signatureDigests);
        return true;
    }

    private static bool TryDecodePackageName(byte[] nameBytes, out string packageName)
    {
        try
        {
            packageName = StrictUtf8.GetString(nameBytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            packageName = string.Empty;
            return false;
        }
    }
}
