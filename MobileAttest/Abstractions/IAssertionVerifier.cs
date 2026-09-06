using System;
using System.Threading;
using System.Threading.Tasks;

namespace MobileAttest.Abstractions;

/// <summary>
/// Verifies an assertion -- the per-request proof that a previously attested key signed
/// this particular request.
/// </summary>
/// <remarks>
/// This is a separate contract from <see cref="IAttestationVerifier"/> because assertion
/// takes different input and yields a different outcome type. Its inputs are raw encoded
/// material so that the contract does not bind to any one platform's object model.
/// </remarks>
public interface IAssertionVerifier
{
    /// <summary>The platform this verifier handles.</summary>
    Platform Platform { get; }

    /// <summary>Verifies one assertion.</summary>
    /// <param name="assertionObject">The encoded assertion as received from the device.</param>
    /// <param name="clientDataHash">The digest binding the assertion to this request.</param>
    /// <param name="attestedPublicKeyDer">
    /// The DER SubjectPublicKeyInfo stored when the key was attested.
    /// </param>
    /// <param name="lastSignCount">
    /// The signature counter stored from the previous accepted assertion. A counter that
    /// fails to advance indicates a cloned key.
    /// </param>
    /// <param name="cancellationToken">Cancels the verification.</param>
    /// <returns>
    /// The outcome. A rejected assertion is reported as a failed
    /// <see cref="AssertionResult"/>, not as an exception.
    /// </returns>
    Task<AssertionResult> VerifyAsync(
        ReadOnlyMemory<byte> assertionObject,
        ReadOnlyMemory<byte> clientDataHash,
        ReadOnlyMemory<byte> attestedPublicKeyDer,
        uint lastSignCount,
        CancellationToken cancellationToken = default);
}
