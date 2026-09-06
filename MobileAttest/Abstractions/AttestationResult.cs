using System;

namespace MobileAttest.Abstractions;

/// <summary>
/// The outcome of verifying a platform attestation. This is the input to the calling
/// backend's issuance or enrolment decision; the library itself makes no such decision.
/// </summary>
public sealed class AttestationResult
{
    private AttestationResult(
        bool isValid,
        AttestationFailureReason reason,
        Platform platform,
        AttestationEnvironment environment,
        ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> publicKeyDer,
        string? appId,
        uint signCount,
        ReadOnlyMemory<byte> receipt)
    {
        IsValid = isValid;
        Reason = reason;
        Platform = platform;
        Environment = environment;
        KeyId = keyId;
        PublicKeyDer = publicKeyDer;
        AppId = appId;
        SignCount = signCount;
        Receipt = receipt;
    }

    /// <summary>Whether every verification step passed.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Why verification failed. <see cref="AttestationFailureReason.None"/> when
    /// <see cref="IsValid"/> is <see langword="true"/>.
    /// </summary>
    public AttestationFailureReason Reason { get; }

    /// <summary>The platform whose mechanism produced the attestation.</summary>
    public Platform Platform { get; }

    /// <summary>The environment the attested key was created in.</summary>
    public AttestationEnvironment Environment { get; }

    /// <summary>The identifier of the attested key. Empty on failure.</summary>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>The attested public key as a DER SubjectPublicKeyInfo. Empty on failure.</summary>
    public ReadOnlyMemory<byte> PublicKeyDer { get; }

    /// <summary>
    /// The application identity the attestation was bound to, or <see langword="null"/>
    /// when verification failed before it could be established.
    /// </summary>
    public string? AppId { get; }

    /// <summary>The signature counter carried by the attestation.</summary>
    public uint SignCount { get; }

    /// <summary>
    /// The platform receipt, when the mechanism issues one. Empty when it does not, or on failure.
    /// </summary>
    public ReadOnlyMemory<byte> Receipt { get; }

    /// <summary>Creates a successful result.</summary>
    /// <param name="platform">The platform whose mechanism produced the attestation.</param>
    /// <param name="environment">The environment the attested key was created in.</param>
    /// <param name="keyId">The identifier of the attested key.</param>
    /// <param name="publicKeyDer">The attested public key as a DER SubjectPublicKeyInfo.</param>
    /// <param name="appId">The application identity the attestation was bound to.</param>
    /// <param name="signCount">The signature counter carried by the attestation.</param>
    /// <param name="receipt">The platform receipt, or empty when the mechanism issues none.</param>
    /// <returns>A result whose <see cref="IsValid"/> is <see langword="true"/>.</returns>
    public static AttestationResult Success(
        Platform platform,
        AttestationEnvironment environment,
        ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> publicKeyDer,
        string? appId,
        uint signCount,
        ReadOnlyMemory<byte> receipt) =>
        new AttestationResult(
            isValid: true,
            reason: AttestationFailureReason.None,
            platform: platform,
            environment: environment,
            keyId: keyId,
            publicKeyDer: publicKeyDer,
            appId: appId,
            signCount: signCount,
            receipt: receipt);

    /// <summary>Creates a failed result carrying no attested material.</summary>
    /// <param name="platform">The platform whose mechanism produced the attestation.</param>
    /// <param name="reason">Why verification failed.</param>
    /// <returns>A result whose <see cref="IsValid"/> is <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="reason"/> is <see cref="AttestationFailureReason.None"/>, which would
    /// describe a failure with no cause.
    /// </exception>
    public static AttestationResult Failure(Platform platform, AttestationFailureReason reason)
    {
        if (reason == AttestationFailureReason.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                "A failed result must name a reason.");
        }

        return new AttestationResult(
            isValid: false,
            reason: reason,
            platform: platform,
            environment: AttestationEnvironment.Unknown,
            keyId: ReadOnlyMemory<byte>.Empty,
            publicKeyDer: ReadOnlyMemory<byte>.Empty,
            appId: null,
            signCount: 0,
            receipt: ReadOnlyMemory<byte>.Empty);
    }
}
