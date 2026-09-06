using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace MobileAttest.Apple;

/// <summary>
/// Object identifiers used by Apple App Attest.
/// </summary>
public static class AppleOids
{
    /// <summary>
    /// The credential certificate extension carrying the attestation nonce.
    /// </summary>
    /// <remarks>
    /// A platform constant published by Apple, not an organisation-specific value, so it
    /// belongs in code rather than in configuration. It is the only Apple extension this
    /// library reads: a credential certificate carries several others, and none of them is
    /// consulted for a security decision.
    /// </remarks>
    public const string AttestationNonceExtension = "1.2.840.113635.100.8.2";

    private static readonly DerObjectIdentifier AttestationNonceExtensionOid =
        new DerObjectIdentifier(AttestationNonceExtension);

    /// <summary>
    /// Reads the octets of the attestation nonce extension out of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to look in.</param>
    /// <param name="extensionOctets">
    /// The extension's octets, or <see langword="null"/> when the certificate carries no
    /// such extension.
    /// </param>
    /// <returns>Whether the extension was present.</returns>
    /// <remarks>
    /// Absence is reported, not thrown. The certificate reaching this method came out of an
    /// attacker-supplied attestation object, so a certificate without the extension is an
    /// expected input rather than an exceptional one.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="certificate"/> is <see langword="null"/>.
    /// </exception>
    public static bool TryGetAttestationNonceExtension(
        X509Certificate certificate,
        out byte[]? extensionOctets)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        Asn1OctetString? value = certificate.GetExtensionValue(AttestationNonceExtensionOid);

        if (value is null)
        {
            extensionOctets = null;
            return false;
        }

        extensionOctets = value.GetOctets();
        return true;
    }
}
