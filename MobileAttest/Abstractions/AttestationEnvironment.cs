namespace MobileAttest.Abstractions;

/// <summary>
/// The environment an attested key was created in.
/// </summary>
/// <remarks>
/// For Apple App Attest this is decided solely by the AAGUID carried in the authenticator
/// data -- never by client-supplied metadata.
/// </remarks>
public enum AttestationEnvironment
{
    /// <summary>The environment could not be determined, or does not apply to this platform.</summary>
    Unknown = 0,

    /// <summary>A development build.</summary>
    Development = 1,

    /// <summary>A production build.</summary>
    Production = 2,
}
