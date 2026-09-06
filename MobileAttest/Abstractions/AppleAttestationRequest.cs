using System;

namespace MobileAttest.Abstractions;

/// <summary>
/// An Apple App Attest attestation, as received from the device at enrolment.
/// </summary>
public sealed class AppleAttestationRequest : AttestationRequest
{
    /// <summary>Initialises an Apple attestation request.</summary>
    /// <param name="keyId">The key identifier the device reported.</param>
    /// <param name="attestationObject">The CBOR-encoded attestation object.</param>
    /// <param name="challenge">The server-issued challenge the attestation must be bound to.</param>
    public AppleAttestationRequest(
        ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> attestationObject,
        ReadOnlyMemory<byte> challenge)
        : base(challenge)
    {
        KeyId = keyId;
        AttestationObject = attestationObject;
    }

    /// <inheritdoc />
    public override Platform Platform => Platform.Apple;

    /// <summary>
    /// The key identifier the device reported. A verifier must confirm it against the
    /// attested key rather than trusting it.
    /// </summary>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>The CBOR-encoded attestation object. Attacker-controlled input.</summary>
    public ReadOnlyMemory<byte> AttestationObject { get; }
}
