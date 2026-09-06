using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace MobileAttest.Trust;

/// <summary>
/// Loads pinned root certificates from PEM supplied by the caller.
/// </summary>
/// <remarks>
/// Roots are configuration. This library ships none and fetches none: a root arrives as
/// text the caller controls, which is what makes the library neutral about which platform
/// or organisation it is verifying for.
/// </remarks>
public static class PemRootStore
{
    /// <summary>
    /// Reads every certificate in a PEM document.
    /// </summary>
    /// <param name="pem">The PEM text, which may hold more than one certificate.</param>
    /// <returns>The certificates, in the order they appear.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// The text could not be parsed, or held no certificate. This is thrown rather than
    /// returning an empty list on purpose: a trust store that quietly comes up empty
    /// disables root pinning everywhere it is used, and nothing downstream would report
    /// it -- every chain would simply fail to pin, or worse, be treated as unpinned.
    /// </exception>
    public static IReadOnlyList<X509Certificate> LoadFromPem(string pem)
    {
        if (pem is null)
        {
            throw new ArgumentNullException(nameof(pem));
        }

        List<object> entries = new List<object>();

        // Parsing and classification are kept apart so that the rejection below is not
        // swallowed by the catch that guards the reader.
        try
        {
            using StringReader text = new StringReader(pem);
            PemReader reader = new PemReader(text);

            while (reader.ReadObject() is object entry)
            {
                entries.Add(entry);
            }
        }
        catch (Exception error) when (error is IOException or FormatException or ArgumentException)
        {
            throw new FormatException("The PEM document could not be parsed.", error);
        }

        List<X509Certificate> certificates = new List<X509Certificate>(entries.Count);

        foreach (object entry in entries)
        {
            if (entry is not X509Certificate certificate)
            {
                throw new FormatException(
                    $"The PEM document holds a {entry.GetType().Name}, which is not a certificate. " +
                    "A trust store must contain certificates only.");
            }

            certificates.Add(certificate);
        }

        if (certificates.Count == 0)
        {
            throw new FormatException(
                "The PEM document held no certificate. An empty trust store would silently " +
                "disable root pinning.");
        }

        return certificates;
    }
}
