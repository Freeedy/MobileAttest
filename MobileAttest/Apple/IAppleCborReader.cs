using System;
using System.Diagnostics.CodeAnalysis;

namespace MobileAttest.Apple;

/// <summary>
/// Decodes the two CBOR objects App Attest defines.
/// </summary>
/// <remarks>
/// <para>
/// This library ships no implementation of this interface, and that is deliberate. The
/// source of CBOR decoding is an open decision: it can be satisfied either by a package
/// or by a decoder written here, and both satisfy this same contract. Drawing the
/// boundary at the Apple object -- rather than at a general CBOR reader -- keeps that
/// decision open, because a general CBOR API would already be one of the two answers.
/// </para>
/// <para>
/// Both methods follow the try pattern for the same reason the authenticator data parser
/// does: the bytes come from the device, so a malformed object is an expected outcome
/// rather than an exceptional one.
/// </para>
/// </remarks>
public interface IAppleCborReader
{
    /// <summary>Decodes an attestation object.</summary>
    /// <param name="cbor">The CBOR-encoded object as received from the device.</param>
    /// <param name="result">
    /// The decoded object, or <see langword="null"/> when the input was rejected.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the input decoded to a complete object; otherwise
    /// <see langword="false"/>. Implementations must not throw on malformed input.
    /// </returns>
    bool TryReadAttestationObject(
        ReadOnlyMemory<byte> cbor,
        [NotNullWhen(true)] out AppleAttestationObject? result);

    /// <summary>Decodes an assertion object.</summary>
    /// <param name="cbor">The CBOR-encoded object as received from the device.</param>
    /// <param name="result">
    /// The decoded object, or <see langword="null"/> when the input was rejected.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the input decoded to a complete object; otherwise
    /// <see langword="false"/>. Implementations must not throw on malformed input.
    /// </returns>
    bool TryReadAssertionObject(
        ReadOnlyMemory<byte> cbor,
        [NotNullWhen(true)] out AppleAssertionObject? result);
}
