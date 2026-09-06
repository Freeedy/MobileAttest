using System;
using System.Collections.Generic;

namespace MobileAttest.Apple;

/// <summary>
/// The decoded content of an App Attest attestation object.
/// </summary>
/// <remarks>
/// This is the shape a decoder must produce, not the encoding itself. Nothing here is
/// trusted: the format string, the chain and the authenticator data are all still to be
/// verified by the caller.
/// </remarks>
public sealed record AppleAttestationObject
{
    /// <summary>
    /// The attestation statement format. Only <c>apple-appattest</c> is verifiable by
    /// this library, and a verifier must check it rather than assume it.
    /// </summary>
    public required string Format { get; init; }

    /// <summary>
    /// The certificate chain from the attestation statement, DER encoded, leaf first.
    /// </summary>
    public required IReadOnlyList<ReadOnlyMemory<byte>> X5c { get; init; }

    /// <summary>The attestation receipt, or empty when the object carried none.</summary>
    public required ReadOnlyMemory<byte> Receipt { get; init; }

    /// <summary>
    /// The raw authenticator data, still encoded. Parsed by
    /// <see cref="AuthenticatorData.TryParse"/> with
    /// <see cref="AuthenticatorDataShape.Attestation"/>, which is the only shape valid here.
    /// </summary>
    public required ReadOnlyMemory<byte> AuthenticatorData { get; init; }
}
