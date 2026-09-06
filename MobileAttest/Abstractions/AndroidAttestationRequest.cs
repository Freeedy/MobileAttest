using System;
using System.Collections.Generic;

namespace MobileAttest.Abstractions;

/// <summary>
/// An Android Key Attestation, as received from the device at enrolment.
/// </summary>
public sealed class AndroidAttestationRequest : AttestationRequest
{
    /// <summary>Initialises an Android attestation request.</summary>
    /// <param name="certificateChain">
    /// The DER-encoded certificate chain, leaf first. Attacker-controlled input.
    /// </param>
    /// <param name="challenge">The server-issued challenge the attestation must be bound to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificateChain"/> is <see langword="null"/>.</exception>
    public AndroidAttestationRequest(
        IReadOnlyList<ReadOnlyMemory<byte>> certificateChain,
        ReadOnlyMemory<byte> challenge)
        : base(challenge)
    {
        CertificateChain = certificateChain ?? throw new ArgumentNullException(nameof(certificateChain));
    }

    /// <inheritdoc />
    public override Platform Platform => Platform.Android;

    /// <summary>
    /// The DER-encoded certificate chain, leaf first. The chain a device sends is not
    /// trusted until it validates to a configured pinned root.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CertificateChain { get; }
}
