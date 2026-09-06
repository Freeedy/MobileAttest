using System;
using System.Formats.Asn1;
using Org.BouncyCastle.X509;

namespace MobileAttest.Apple;

/// <summary>
/// Reads the nonce out of the credential certificate's App Attest extension.
/// </summary>
/// <remarks>
/// <para>The structure is small and fixed:</para>
/// <code>
/// SEQUENCE {
///     [1] EXPLICIT OCTET STRING nonce
/// }
/// </code>
/// <para><b>There is no "last 32 bytes" fallback, and that is the point of this file</b></para>
/// <para>
/// A shorter implementation is widely suggested: skip the structure and take the final 32
/// bytes of the extension. It is not written here, and it must not be added. The extension
/// arrives inside a certificate an attacker chose to send, and a reader that looks only at
/// the tail lets that attacker append whatever it likes -- the structure it parses becomes
/// decoration, and the bytes that decide the comparison become the ones nobody checked.
/// Parsing the structure, and rejecting anything left over at either level, closes that
/// route: there is exactly one reading of a given extension, or there is a rejection.
/// </para>
/// <para>
/// The same rule is why an extension that cannot be read is a rejection rather than a step
/// that is skipped. A missing nonce is not a smaller attestation; it is an attestation with
/// nothing binding it to the challenge that was issued.
/// </para>
/// </remarks>
internal static class AppleNonceExtension
{
    /// <summary>
    /// The explicit context-specific tag the nonce is wrapped in.
    /// </summary>
    private static readonly Asn1Tag NonceTag =
        new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);

    /// <summary>
    /// Reads the nonce from a certificate, treating an absent extension and an unreadable
    /// one the same way.
    /// </summary>
    /// <param name="certificate">The credential certificate from the attestation statement.</param>
    /// <param name="nonce">
    /// The nonce octets, or <see langword="null"/> when there was nothing to read.
    /// </param>
    /// <returns>Whether a nonce was read.</returns>
    /// <remarks>
    /// The two outcomes are not told apart here, unlike the Android key attestation
    /// extension where they are. There the distinction is worth carrying: a certificate with
    /// no extension is usually an ordinary key or the wrong element of the chain. Here the
    /// certificate has already been taken from an object that declared itself an App Attest
    /// attestation and validated to a pinned root, so a credential certificate without this
    /// extension is not an ordinary certificate -- it is one that cannot be what the object
    /// said it was. Both answers are the same answer, and one reason leaks less about which
    /// piece of a forgery was noticed.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="certificate"/> is <see langword="null"/>.
    /// </exception>
    internal static bool TryRead(X509Certificate certificate, out byte[]? nonce)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (!AppleOids.TryGetAttestationNonceExtension(certificate, out byte[]? extensionOctets))
        {
            nonce = null;
            return false;
        }

        return TryParse(extensionOctets!, out nonce);
    }

    /// <summary>
    /// Parses the extension's octets.
    /// </summary>
    /// <param name="extensionOctets">The octets as carried by the certificate.</param>
    /// <param name="nonce">
    /// The nonce octets, or <see langword="null"/> when the input was rejected.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the input matched the structure exactly, with nothing
    /// left over at either level; otherwise <see langword="false"/>. This method does not
    /// throw on malformed input.
    /// </returns>
    /// <remarks>
    /// The nonce's length is not checked here. Whether 32 bytes were carried is settled by
    /// the comparison the verifier makes against a SHA-256 digest, which refuses a length
    /// mismatch; asking the question twice would put the answer in two places and leave one
    /// of them to drift.
    /// </remarks>
    internal static bool TryParse(ReadOnlyMemory<byte> extensionOctets, out byte[]? nonce)
    {
        nonce = null;

        // The reader reports every encoding fault by throwing. That is the right shape for a
        // reader and the wrong shape for a caller holding device bytes, so the whole parse is
        // wrapped once, here, at the boundary the outside world enters through. Nothing below
        // recurses: the depth is fixed by the schema, so a deeply nested input fails at the
        // first element whose type does not match rather than walking the stack down.
        try
        {
            AsnReader document = new AsnReader(extensionOctets, AsnEncodingRules.DER);
            AsnReader body = document.ReadSequence();

            // Trailing bytes after the SEQUENCE are rejected rather than ignored. This is the
            // outer half of what makes the tail-reading shortcut impossible to reintroduce
            // by accident.
            document.ThrowIfNotEmpty();

            AsnReader tagged = body.ReadSequence(NonceTag);

            // And the inner half: nothing may follow the tagged element inside the SEQUENCE,
            // and nothing may follow the OCTET STRING inside the tagged element.
            body.ThrowIfNotEmpty();

            byte[] value = tagged.ReadOctetString();
            tagged.ThrowIfNotEmpty();

            nonce = value;
            return true;
        }
        catch (AsnContentException)
        {
            nonce = null;
            return false;
        }
    }
}
