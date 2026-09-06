using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;

namespace MobileAttest.Apple;

/// <summary>
/// The library's only CBOR decoder, reading the two objects App Attest defines with
/// <see cref="CborReader"/> from <c>System.Formats.Cbor</c>.
/// </summary>
/// <remarks>
/// <para><b>Why a package and not a decoder written here</b></para>
/// <para>
/// The bytes reaching this type are entirely attacker-controlled, and a CBOR decoder is
/// exactly the kind of code where a boundary mistake becomes a memory-safety incident.
/// Microsoft's package is the same decoder the platform ships, is serviced on the .NET
/// release cadence, and adds nothing to the dependency closure on this target framework.
/// The alternative -- a minimal decoder written here -- would have put every parse defect
/// and a permanent fuzzing obligation on this project instead.
/// </para>
/// <para><b>The shapes read</b></para>
/// <code>
/// attestation  {"fmt": tstr, "attStmt": {"x5c": [bstr, ...], "receipt": bstr}, "authData": bstr}
/// assertion    {"signature": bstr, "authenticatorData": bstr}
/// </code>
/// <para>
/// Only <c>receipt</c> is optional; every other member is required, and an object missing
/// one is rejected rather than returned with that field empty.
/// </para>
/// <para><b>Strict conformance, and what it does not cover</b></para>
/// <para>
/// The reader runs in <see cref="CborConformanceMode.Strict"/>, which adds three checks
/// over well-formedness: a map may not repeat a key, text strings must be valid UTF-8, and
/// simple values must be minimally encoded. Measured against the real device capture: the
/// whole object decodes in this mode with nothing left over, so the strictness costs no
/// genuine traffic.
/// </para>
/// <para>
/// Strict does <b>not</b> reject trailing bytes -- measured: a reader handed one valid map
/// followed by a stray byte reports <c>Finished</c> and leaves the byte unread. So the
/// trailing-byte rejection below is this type's own check, not the package's. Without it
/// one input would have two readings, and whatever a caller stored or compared afterwards
/// would not cover the difference.
/// </para>
/// <para><b>Unknown members are rejected, not skipped</b></para>
/// <para>
/// A member this decoder does not know is a rejection. Skipping it would let a sender
/// attach content that no verifier downstream ever looks at, which is the same smuggling
/// route as a trailing byte, taken one level in. It also keeps <c>CborReader.SkipValue</c>
/// out of this file: nothing here walks a structure whose shape the sender chose, so a
/// deeply nested input is refused at the first member that is not the type expected --
/// before any traversal -- rather than descended into.
/// </para>
/// <para><b>Indefinite-length encodings are accepted</b></para>
/// <para>
/// Strict permits them, and this decoder allows them, so the same object can arrive under
/// more than one encoding. That changes no check made here or downstream: every value is
/// returned decoded, and App Attest signs the decoded authenticator data rather than the
/// encoding that carried it. Rejecting them would instead be a bet on Apple's encoder
/// never emitting one, across iOS versions we cannot measure. The consequence for a caller
/// is one rule: key a replay cache on the credential identifier and the counter, never on
/// the raw bytes of the object.
/// </para>
/// <para><b>Nothing here is trusted</b></para>
/// <para>
/// This type answers "did these bytes decode", never "is this attestation genuine". The
/// format string is returned as read and is not compared to <c>apple-appattest</c>, the
/// certificates are returned as bytes and are not parsed, and the receipt is not examined
/// at all. Those are the verifiers' decisions.
/// </para>
/// </remarks>
public sealed class AppleCborReader : IAppleCborReader
{
    /// <summary>
    /// The ceiling on how many certificates an attestation statement may carry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The real capture carries two: a credential certificate and one CA. Ten leaves room
    /// for Apple to add a tier without letting a sender spend our time by padding.
    /// </para>
    /// <para>
    /// It is applied while reading rather than afterwards. An array header can declare far
    /// more elements than a chain ever has, so counting them out first would mean doing the
    /// work the sender asked for before deciding whether to.
    /// </para>
    /// <para>
    /// This is deliberately its own number rather than
    /// <see cref="Trust.ChainValidationPolicy.MaxChainLength"/>. That one is a per-call
    /// validation limit a caller may raise; this one is a fixed ceiling on how much of a
    /// device's input is decoded at all. Deriving this from that policy's default would
    /// couple them only in appearance -- a caller raising the policy would find its longer
    /// chains rejected here instead, before the validator it configured ever saw them.
    /// </para>
    /// </remarks>
    public const int MaxCertificateChainLength = 10;

    private const string FormatKey = "fmt";
    private const string StatementKey = "attStmt";
    private const string AttestationAuthenticatorDataKey = "authData";
    private const string CertificateChainKey = "x5c";
    private const string ReceiptKey = "receipt";
    private const string SignatureKey = "signature";
    private const string AssertionAuthenticatorDataKey = "authenticatorData";

    /// <inheritdoc />
    public bool TryReadAttestationObject(
        ReadOnlyMemory<byte> cbor,
        [NotNullWhen(true)] out AppleAttestationObject? result)
    {
        result = null;

        try
        {
            CborReader reader = CreateReader(cbor);

            if (!TryReadAttestationObjectCore(reader, out AppleAttestationObject? decoded)
                || !IsFullyConsumed(reader))
            {
                return false;
            }

            result = decoded;
            return true;
        }
        catch (Exception error) when (IsRejection(error))
        {
            return false;
        }
    }

    /// <inheritdoc />
    public bool TryReadAssertionObject(
        ReadOnlyMemory<byte> cbor,
        [NotNullWhen(true)] out AppleAssertionObject? result)
    {
        result = null;

        try
        {
            CborReader reader = CreateReader(cbor);

            if (!TryReadAssertionObjectCore(reader, out AppleAssertionObject? decoded)
                || !IsFullyConsumed(reader))
            {
                return false;
            }

            result = decoded;
            return true;
        }
        catch (Exception error) when (IsRejection(error))
        {
            return false;
        }
    }

    /// <summary>Creates the reader every read in this type runs on.</summary>
    /// <remarks>
    /// <paramref name="cbor"/> is not copied. Nothing is returned as a slice of it -- every
    /// value below comes back as an array the reader allocated -- so a caller reusing its
    /// buffer after the call cannot change what was decoded.
    /// </remarks>
    private static CborReader CreateReader(ReadOnlyMemory<byte> cbor) =>
        new CborReader(cbor, CborConformanceMode.Strict, allowMultipleRootLevelValues: false);

    /// <summary>
    /// Says whether the encoding held exactly one object and nothing after it.
    /// </summary>
    /// <remarks>
    /// Measured, and the reason this is asked explicitly: the reader reports
    /// <see cref="CborReaderState.Finished"/> after a complete root value whether or not
    /// bytes follow it, so "finished" is not the same question as "consumed".
    /// </remarks>
    private static bool IsFullyConsumed(CborReader reader) => reader.BytesRemaining == 0;

    /// <summary>
    /// Says whether an exception means the input was bad rather than that this code is.
    /// </summary>
    /// <remarks>
    /// <para>Measured against the package, not assumed. Every malformed input probed --
    /// empty, truncated, a byte string longer than the buffer, an array declaring four
    /// billion elements, a tag where a map was expected, a duplicate key, invalid UTF-8,
    /// fifty thousand nested arrays -- raised exactly one of these two types:</para>
    /// <list type="bullet">
    ///   <item>
    ///     <see cref="CborContentException"/> -- the bytes are not well-formed CBOR, or
    ///     break a strict-mode rule.
    ///   </item>
    ///   <item>
    ///     <see cref="InvalidOperationException"/> -- the bytes are well-formed but the
    ///     next item is not the type this decoder asked for.
    ///   </item>
    /// </list>
    /// <para>
    /// The filter is deliberately not <c>catch (Exception)</c>. A
    /// <see cref="NullReferenceException"/> or an <see cref="IndexOutOfRangeException"/>
    /// escaping from here would be a defect in this file, and returning
    /// <see langword="false"/> for it would hide that defect behind a rejection that looks
    /// exactly like a rejected device.
    /// </para>
    /// </remarks>
    private static bool IsRejection(Exception error) =>
        error is CborContentException or InvalidOperationException;

    /// <summary>Reads the attestation object's outer map.</summary>
    /// <remarks>
    /// The loop is driven by <see cref="CborReader.PeekState"/> rather than by the count
    /// from the map header, so a definite-length and an indefinite-length map are read the
    /// same way. It cannot run long: every iteration either consumes one of the three known
    /// members for the first time or returns, so it ends within four passes whatever the
    /// header claimed.
    /// </remarks>
    private static bool TryReadAttestationObjectCore(
        CborReader reader,
        [NotNullWhen(true)] out AppleAttestationObject? result)
    {
        result = null;

        string? format = null;
        IReadOnlyList<ReadOnlyMemory<byte>>? certificateChain = null;
        ReadOnlyMemory<byte> receipt = ReadOnlyMemory<byte>.Empty;
        byte[]? authenticatorData = null;
        bool statementSeen = false;

        reader.ReadStartMap();

        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case FormatKey when format is null:
                    format = reader.ReadTextString();
                    break;

                case StatementKey when !statementSeen:
                    statementSeen = true;

                    if (!TryReadAttestationStatement(reader, out certificateChain, out receipt))
                    {
                        return false;
                    }

                    break;

                case AttestationAuthenticatorDataKey when authenticatorData is null:
                    authenticatorData = reader.ReadByteString();
                    break;

                default:
                    // An unknown member, or a second copy of one already read. Strict mode
                    // also refuses the repeat, but the guards above make that this
                    // decoder's answer rather than a behaviour inherited from a conformance
                    // mode someone could later relax.
                    return false;
            }
        }

        reader.ReadEndMap();

        if (format is null || certificateChain is null || authenticatorData is null)
        {
            return false;
        }

        result = new AppleAttestationObject
        {
            Format = format,
            X5c = certificateChain,
            Receipt = receipt,
            AuthenticatorData = authenticatorData,
        };
        return true;
    }

    /// <summary>Reads the <c>attStmt</c> map.</summary>
    /// <param name="reader">The reader, positioned at the statement's map header.</param>
    /// <param name="certificateChain">The decoded chain, or null when none was present.</param>
    /// <param name="receipt">The receipt, or empty when the statement carried none.</param>
    private static bool TryReadAttestationStatement(
        CborReader reader,
        out IReadOnlyList<ReadOnlyMemory<byte>>? certificateChain,
        out ReadOnlyMemory<byte> receipt)
    {
        certificateChain = null;
        receipt = ReadOnlyMemory<byte>.Empty;
        bool receiptSeen = false;

        reader.ReadStartMap();

        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case CertificateChainKey when certificateChain is null:
                    if (!TryReadCertificateChain(reader, out certificateChain))
                    {
                        return false;
                    }

                    break;

                case ReceiptKey when !receiptSeen:
                    // Optional by the contract on AppleAttestationObject.Receipt: absent
                    // leaves it empty. Present-but-empty and absent are the same value to a
                    // caller, and neither is this type's business to judge.
                    receiptSeen = true;
                    receipt = reader.ReadByteString();
                    break;

                default:
                    return false;
            }
        }

        reader.ReadEndMap();

        return certificateChain is not null;
    }

    /// <summary>Reads the <c>x5c</c> array of DER certificates.</summary>
    /// <remarks>
    /// An empty array is rejected. It is well-formed CBOR, but it would hand a verifier a
    /// chain with no leaf to read and no certificate to pin, and the first thing that
    /// indexes it would fault on input a device chose. The same reasoning the trust store
    /// applies to an empty root list applies here.
    /// </remarks>
    private static bool TryReadCertificateChain(
        CborReader reader,
        out IReadOnlyList<ReadOnlyMemory<byte>>? certificateChain)
    {
        certificateChain = null;

        List<ReadOnlyMemory<byte>> certificates = new List<ReadOnlyMemory<byte>>();

        reader.ReadStartArray();

        while (reader.PeekState() != CborReaderState.EndArray)
        {
            if (certificates.Count == MaxCertificateChainLength)
            {
                return false;
            }

            certificates.Add(reader.ReadByteString());
        }

        reader.ReadEndArray();

        if (certificates.Count == 0)
        {
            return false;
        }

        certificateChain = certificates;
        return true;
    }

    /// <summary>Reads the assertion object's map.</summary>
    private static bool TryReadAssertionObjectCore(
        CborReader reader,
        [NotNullWhen(true)] out AppleAssertionObject? result)
    {
        result = null;

        byte[]? signature = null;
        byte[]? authenticatorData = null;

        reader.ReadStartMap();

        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case SignatureKey when signature is null:
                    signature = reader.ReadByteString();
                    break;

                case AssertionAuthenticatorDataKey when authenticatorData is null:
                    authenticatorData = reader.ReadByteString();
                    break;

                default:
                    return false;
            }
        }

        reader.ReadEndMap();

        // Both members are required. An assertion missing either one is not a smaller
        // assertion, it is an object no verifier could act on: there would be nothing to
        // check the signature over, or no signature to check.
        if (signature is null || authenticatorData is null)
        {
            return false;
        }

        result = new AppleAssertionObject
        {
            Signature = signature,
            AuthenticatorData = authenticatorData,
        };
        return true;
    }
}
