using System;

namespace MobileAttest.Abstractions;

/// <summary>
/// Everything a verifier needs to check one attestation, independent of platform.
/// </summary>
/// <remarks>
/// The challenge is supplied by the caller. Issuing and replaying challenges is out of
/// this library's scope: it receives the value it is asked to match, and nothing more.
/// </remarks>
public abstract class AttestationRequest
{
    /// <summary>Initialises the platform-independent part of a request.</summary>
    /// <param name="challenge">The server-issued challenge the attestation must be bound to.</param>
    protected AttestationRequest(ReadOnlyMemory<byte> challenge)
    {
        Challenge = challenge;
    }

    /// <summary>The platform whose mechanism produced this request.</summary>
    public abstract Platform Platform { get; }

    /// <summary>The server-issued challenge the attestation must be bound to.</summary>
    public ReadOnlyMemory<byte> Challenge { get; }
}
