using System;
using System.Threading;
using System.Threading.Tasks;

namespace MobileAttest.Abstractions;

/// <summary>
/// Verifies a platform attestation -- the one-time proof that a key is genuine, was
/// created on real hardware, and belongs to the expected application.
/// </summary>
/// <remarks>
/// The method is asynchronous because revocation status for at least one platform is a
/// network lookup. No implementation in this library performs one today; the shape is
/// asynchronous so that adding it later is not a breaking change to this contract.
/// </remarks>
public interface IAttestationVerifier
{
    /// <summary>The platform this verifier handles.</summary>
    Platform Platform { get; }

    /// <summary>Verifies one attestation.</summary>
    /// <param name="request">The attestation to verify.</param>
    /// <param name="cancellationToken">Cancels the verification.</param>
    /// <returns>
    /// The outcome. A rejected attestation is reported as a failed
    /// <see cref="AttestationResult"/>, not as an exception.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    Task<AttestationResult> VerifyAsync(AttestationRequest request, CancellationToken cancellationToken = default);
}
