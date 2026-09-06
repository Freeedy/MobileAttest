using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace MobileAttest.Trust;

/// <summary>
/// Validates a device-supplied certificate chain against roots the caller pinned.
/// </summary>
/// <remarks>
/// Both platforms this library verifies begin with the same question, so it is asked in
/// one place. Two verifiers each carrying their own chain logic would be two trust
/// engines: two places to get it wrong, and one of them left behind whenever the other is
/// fixed.
/// </remarks>
public interface ICertificateChainValidator
{
    /// <summary>
    /// Decides whether a chain reaches one of the pinned roots.
    /// </summary>
    /// <param name="derChain">
    /// The chain as DER, leaf first. Every element comes from the device, so this may be
    /// empty, hold nulls, or hold bytes that are not certificates.
    /// </param>
    /// <param name="trustedRoots">
    /// The roots the caller pins. This library ships none and fetches none. An empty or
    /// absent set is a rejection, never a pass: "no root to check against" must not read
    /// as "nothing objected".
    /// </param>
    /// <returns>
    /// The outcome, carrying a reason when the chain was rejected. Malformed input is
    /// answered with a reason rather than an exception, because the input is attacker
    /// controlled.
    /// </returns>
    ChainValidationResult Validate(
        IReadOnlyList<byte[]> derChain,
        IReadOnlyList<X509Certificate> trustedRoots);
}
