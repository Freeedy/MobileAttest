namespace MobileAttest.Abstractions;

/// <summary>
/// Why an attestation or assertion was rejected.
/// </summary>
/// <remarks>
/// This is an enum rather than free text on purpose: a caller may return it to a client
/// without leaking internal detail. Detail belongs in the server log, not in the response.
/// </remarks>
public enum AttestationFailureReason
{
    /// <summary>No failure. Only ever carried by a successful result.</summary>
    None = 0,

    /// <summary>The attestation or assertion object could not be decoded.</summary>
    MalformedAttestationObject = 1,

    /// <summary>The attestation statement format is not one this library verifies.</summary>
    UnsupportedAttestationFormat = 2,

    /// <summary>The authenticator data was truncated, or declared a length its buffer cannot hold.</summary>
    MalformedAuthenticatorData = 3,

    /// <summary>The certificate chain did not validate up to a trusted root.</summary>
    CertificateChainInvalid = 4,

    /// <summary>The chain validated, but its root is not one of the configured pinned roots.</summary>
    RootNotPinned = 5,

    /// <summary>A certificate in the chain is outside its validity window.</summary>
    CertificateExpired = 6,

    /// <summary>Revocation status says the attestation key is revoked.</summary>
    CertificateRevoked = 7,

    /// <summary>Revocation status could not be established, and policy requires it.</summary>
    RevocationStatusUnavailable = 8,

    /// <summary>The nonce embedded in the attestation does not match the one derived from the challenge.</summary>
    NonceMismatch = 9,

    /// <summary>The challenge carried by the attestation does not match the expected challenge.</summary>
    ChallengeMismatch = 10,

    /// <summary>The relying-party identifier hash does not match the configured application identity.</summary>
    RpIdHashMismatch = 11,

    /// <summary>The bundle identifier is not in the configured allowlist.</summary>
    BundleIdNotAllowed = 12,

    /// <summary>A development-environment key was presented while production was required.</summary>
    DevelopmentKeyInProduction = 13,

    /// <summary>The key identifier does not match the attested public key.</summary>
    KeyIdMismatch = 14,

    /// <summary>The attested public key does not match the one the caller expected.</summary>
    PublicKeyMismatch = 15,

    /// <summary>The signature did not verify under the attested key.</summary>
    SignatureInvalid = 16,

    /// <summary>The signature counter did not hold the value attestation requires.</summary>
    SignCountInvalid = 17,

    /// <summary>The signature counter did not increase, which indicates a cloned key.</summary>
    SignCountNotIncreased = 18,

    /// <summary>The leaf certificate carries no key attestation extension.</summary>
    AttestationExtensionMissing = 19,

    /// <summary>The key attestation extension is present but could not be parsed.</summary>
    MalformedAttestationExtension = 20,

    /// <summary>The key's security level is below what policy requires.</summary>
    SecurityLevelInsufficient = 21,

    /// <summary>The key was imported rather than generated inside the secure hardware.</summary>
    KeyNotHardwareGenerated = 22,

    /// <summary>Verified boot state is not <c>Verified</c>, so hardware claims cannot be trusted.</summary>
    BootStateNotVerified = 23,

    /// <summary>The device reports itself as unlocked.</summary>
    DeviceNotLocked = 24,

    /// <summary>The application signing digest is not in the configured allowlist.</summary>
    SignatureDigestNotAllowed = 25,
}
