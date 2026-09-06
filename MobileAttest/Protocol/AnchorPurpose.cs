namespace MobileAttest.Protocol;

/// <summary>
/// What a proof-of-possession signature is being produced for.
/// </summary>
/// <remarks>
/// The purpose is part of the signed message, which is what stops a signature produced
/// for one operation from being replayed as proof of another. It is an enum rather than a
/// free string so that a typo becomes a compile error instead of a silently different
/// digest that still verifies against itself.
/// </remarks>
public enum AnchorPurpose
{
    /// <summary>Proof bound to issuing an authentication token.</summary>
    AuthToken = 1,

    /// <summary>Proof bound to a gate verification.</summary>
    GateVerify = 2,

    /// <summary>Proof bound to binding a key.</summary>
    KeyBinding = 3,
}
