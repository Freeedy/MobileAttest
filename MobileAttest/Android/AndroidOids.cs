using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace MobileAttest.Android;

/// <summary>
/// Object identifiers used by Android Key Attestation.
/// </summary>
public static class AndroidOids
{
    /// <summary>
    /// The certificate extension carrying the KeyDescription structure, which holds the
    /// attestation challenge, the security level and the authorisation lists.
    /// </summary>
    /// <remarks>
    /// This is a platform constant published by Google, not an organisation-specific
    /// value, so it belongs in code rather than in configuration.
    /// </remarks>
    public const string KeyAttestationExtension = "1.3.6.1.4.1.11129.2.1.17";

    private static readonly DerObjectIdentifier KeyAttestationExtensionOid =
        new DerObjectIdentifier(KeyAttestationExtension);

    /// <summary>
    /// Reads the octets of the key attestation extension out of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to look in.</param>
    /// <param name="extensionOctets">
    /// The extension's octets, or <see langword="null"/> when the certificate carries no
    /// such extension.
    /// </param>
    /// <returns>Whether the extension was present.</returns>
    /// <remarks>
    /// Absence is reported, not thrown. A certificate without this extension is an ordinary
    /// outcome -- an ordinary key, or the wrong certificate from the chain -- and the caller
    /// needs to be able to say which failure it was. See
    /// <see cref="KeyDescription.TryReadFrom"/>, which turns that distinction into two
    /// separate failure reasons.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="certificate"/> is <see langword="null"/>.
    /// </exception>
    public static bool TryGetKeyAttestationExtension(
        X509Certificate certificate,
        out byte[]? extensionOctets)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        Asn1OctetString? value = certificate.GetExtensionValue(KeyAttestationExtensionOid);

        if (value is null)
        {
            extensionOctets = null;
            return false;
        }

        extensionOctets = value.GetOctets();
        return true;
    }
}
