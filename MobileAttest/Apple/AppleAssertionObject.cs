using System;

namespace MobileAttest.Apple;

/// <summary>
/// The decoded content of an App Attest assertion object.
/// </summary>
public sealed record AppleAssertionObject
{
    /// <summary>The signature over the authenticator data and the client data hash.</summary>
    public required ReadOnlyMemory<byte> Signature { get; init; }

    /// <summary>
    /// The raw authenticator data, still encoded. Parsed by
    /// <see cref="AuthenticatorData.TryParse"/> with
    /// <see cref="AuthenticatorDataShape.Assertion"/>, which is the only shape valid here.
    /// </summary>
    public required ReadOnlyMemory<byte> AuthenticatorData { get; init; }
}
