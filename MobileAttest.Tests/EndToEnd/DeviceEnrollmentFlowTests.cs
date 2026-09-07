using MobileAttest.Abstractions;
using MobileAttest.Android;
using MobileAttest.Apple;
using MobileAttest.Tests.TestSupport;
using MobileAttest.Trust;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.EndToEnd;

/// <summary>
/// The whole device enrollment flow, on both platforms, written so that a reader can see
/// <b>where every value comes from</b> before writing a line of integration code.
/// </summary>
/// <remarks>
/// <para>
/// Four origins exist in this flow, and every value in these tests belongs to exactly one of
/// them. The names in the test bodies say which, so the origin is readable without tracing a
/// variable back to its declaration:
/// </para>
/// <list type="table">
///   <item>
///     <term><c>heldOnTheServer</c></term>
///     <description>Configuration that exists before any device talks to the backend. It is
///     deployment data, not device data, and nothing the app sends may change it.</description>
///   </item>
///   <item>
///     <term><c>issuedByTheServer</c></term>
///     <description>A random value the backend mints, hands out, and remembers -- the
///     enrollment challenge and the per-operation nonce. The app echoes it back; the backend
///     compares it against what it issued, never against what came back.</description>
///   </item>
///   <item>
///     <term><c>fromTheApp</c></term>
///     <description>The bytes that actually cross the wire. Held in the message types below
///     so that "the device sent this" is a fact of the type system rather than a comment.</description>
///   </item>
///   <item>
///     <term><c>storedRecord</c></term>
///     <description>What the backend writes to its database after a successful enrollment,
///     and reads back on every later operation.</description>
///   </item>
/// </list>
///
/// <para><b>The contract, per platform</b></para>
/// <para>
/// <b>Apple, enrollment.</b> Held on the server: team identifier, bundle identifier
/// allowlist, the production switch, and the pinned Apple root -- this library ships no root
/// and downloads none. Issued by the server: the challenge. From the app: the key identifier
/// and the CBOR attestation object. Stored afterwards: key identifier, attested public key,
/// application identifier, a sign counter starting at zero, and the receipt.
/// </para>
/// <para>
/// <b>Apple, every later operation.</b> Issued by the server: a fresh nonce. From the app:
/// the assertion object and the request body it wants performed. <b>Computed by the server,
/// never accepted from the app:</b> the client data hash, which this capture measures as the
/// SHA-256 of the request body followed by the nonce. Read from storage: the attested public
/// key and the last sign counter. Written back: the new counter, and only when it increased.
/// </para>
/// <para>
/// <b>Android, enrollment.</b> Held on the server: the allowed signing digests, the StrongBox
/// switch, the pinned Google root, and a revocation policy -- which has no default, because
/// whether an unverifiable key is acceptable is the deployment's decision. Issued by the
/// server: the challenge. From the app: the certificate chain. Stored afterwards: key
/// identifier, attested public key, and the package name.
/// </para>
/// <para>
/// <b>Android has no later operation in this library.</b> There is no counter, no receipt and
/// no assertion verifier on that side -- <see cref="IAssertionVerifier"/> is implemented for
/// Apple only. A deployment that needs per-operation proof on Android signs with the attested
/// key and verifies that itself. The Android test below asserts this rather than leaving a
/// reader to discover it during integration.
/// </para>
///
/// <para><b>What this library does not do, and the backend must</b></para>
/// <para>
/// Minting challenges and nonces, storing them, expiring them and refusing a second use;
/// persisting the sign counter; and keeping the device records themselves. Nonce handling was
/// deliberately placed outside this library, so a value arrives here as a parameter and the
/// tests below mint and remember it exactly where a backend would.
/// </para>
///
/// <para><b>The rule these tests hold to</b></para>
/// <para>
/// <b>After enrollment returns, nothing reads the vector again.</b> The signed operation is
/// checked against the key, the counter and the application identity that enrollment handed
/// back. A verifier pair can pass every step in isolation and still not connect -- a key
/// returned in one encoding and expected in another, a counter returned that the next call
/// cannot consume. Nothing here would survive that.
/// </para>
///
/// <para><b>Where a captured vector differs from a live device</b></para>
/// <para>
/// A live backend issues a random challenge and a random nonce. These tests take both from
/// the capture, because only the device holding the attested key could answer a fresh one.
/// Everything downstream -- the hash the server recomputes, the record it stores, the counter
/// it advances -- runs exactly as it would in production, and the controls at the end of each
/// test show the comparisons bite rather than merely being executed.
/// </para>
/// </remarks>
public class DeviceEnrollmentFlowTests
{
    /// <summary>
    /// An instant inside the validity window of the vector Apple credential certificate,
    /// which lives for about three days. Wall-clock time is never used: the capture would
    /// begin failing on its own, and a test that rots is not evidence of anything.
    /// </summary>
    private static readonly DateTimeOffset AppleEnrollmentTime =
        new DateTimeOffset(2026, 9, 4, 12, 0, 0, TimeSpan.Zero);

    /// <summary>The same idea for the Android chain, whose window is a different one.</summary>
    private static FixedTimeProvider AndroidEnrollmentTime => FixedTimeProvider.AtUtc(2026, 9, 5, 12);

    // =========================================================================== Apple

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task Flow_AppleDevice_EnrollThenSignedOperation_UsesOnlyStoredMaterial()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        // --------------------------------------------------------------------------------
        // HELD ON THE SERVER, before any device talks to it.
        //
        // Every one of these is deployment configuration. None of it is read from the
        // message the app sends -- if it were, an app could nominate its own team, its own
        // bundle identifier or its own trust anchor.
        // --------------------------------------------------------------------------------
        AppleAttestOptions heldOnTheServer = new AppleAttestOptions
        {
            TeamId = vector.TeamId,
            BundleIdAllowlist = new[] { vector.BundleId },

            // Measured, not assumed: this capture is an Xcode build, so its AAGUID says
            // development. A production deployment sets this to true, and the same object is
            // then refused -- which the per-step tests already show.
            RequireProduction = false,

            // No default root exists, deliberately. Supplying it is real integration work,
            // and it is the deployment that decides what it trusts.
            PinnedRootCertificates = new[] { LoadCertificate(TestVectors.AppleRootPath) },
        };

        // --------------------------------------------------------------------------------
        // ISSUED BY THE SERVER. Minted here, remembered here, compared against here. The
        // backend owns the store this stands in for; the library never sees it.
        // --------------------------------------------------------------------------------
        byte[] challengeIssuedByTheServer = vector.AttestationChallenge;

        // --------------------------------------------------------------------------------
        // FROM THE APP. These two fields are the entire enrollment message on iOS.
        // --------------------------------------------------------------------------------
        AppleEnrollment fromTheApp = new AppleEnrollment(
            KeyId: Convert.FromBase64String(vector.KeyIdBase64),
            AttestationObject: vector.AttestationObject);

        AttestationResult enrollment = await new AppleAppAttestVerifier(heldOnTheServer)
            .VerifyAsync(
                new AppleAttestationRequest(
                    fromTheApp.KeyId,
                    fromTheApp.AttestationObject,
                    challengeIssuedByTheServer),
                AppleEnrollmentTime);

        Assert.True(enrollment.IsValid, $"enrollment was refused with {enrollment.Reason}");
        Assert.Equal(Platform.Apple, enrollment.Platform);
        Assert.Equal(AttestationEnvironment.Development, enrollment.Environment);

        // --------------------------------------------------------------------------------
        // STORED BY THE SERVER. This is the whole record. From this line on, the vector is
        // not consulted for any value that a live backend would have to have persisted.
        // --------------------------------------------------------------------------------
        EnrolledDevice storedRecord = EnrolledDevice.From(enrollment);

        Assert.Equal(32, storedRecord.KeyId.Length);
        Assert.NotEmpty(storedRecord.PublicKeyDer);
        Assert.Equal($"{vector.TeamId}.{vector.BundleId}", storedRecord.AppId);
        Assert.Equal(0u, storedRecord.SignCount);

        // The receipt is the caller to keep -- Apple servers accept it later for fraud
        // metrics. Nothing in this library consumes it, so the flow only shows it arriving
        // intact and being stored.
        Assert.Equal(3966, storedRecord.Receipt.Length);

        // ================================================================================
        // A LATER OPERATION. Days later, a different process, nothing in memory.
        // ================================================================================

        // ISSUED BY THE SERVER -- a fresh nonce, for this one operation.
        byte[] nonceIssuedByTheServer = vector.AssertionNonce;

        // FROM THE APP -- the signed blob and the request it wants performed.
        AppleOperation operationFromTheApp = new AppleOperation(
            AssertionObject: vector.AssertionObject,
            RequestBody: vector.AssertionRequestBody);

        // --------------------------------------------------------------------------------
        // COMPUTED BY THE SERVER, never accepted from the app. If the app supplied this
        // digest, it would be choosing what its own signature is checked against.
        // --------------------------------------------------------------------------------
        byte[] clientDataHashComputedByTheServer = AssertionBuilder.Sha256(
            operationFromTheApp.RequestBody,
            nonceIssuedByTheServer);

        // Measured against the capture: this is the construction the device actually signed.
        // Without this line the test would show only that some digest verifies.
        Assert.Equal(vector.AssertionClientDataHash, clientDataHashComputedByTheServer);

        // --------------------------------------------------------------------------------
        // VERIFIED AGAINST STORAGE. The key and the counter come from the record, so a break
        // in the join between the two verifiers surfaces here and nowhere else.
        // --------------------------------------------------------------------------------
        AppleAssertionVerifier assertionVerifier = new AppleAssertionVerifier(storedRecord.AppId);

        AssertionResult operation = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            clientDataHashComputedByTheServer,
            storedRecord.PublicKeyDer,
            storedRecord.SignCount);

        Assert.True(operation.IsValid, $"the signed operation was refused with {operation.Reason}");
        Assert.True(
            operation.NewSignCount > storedRecord.SignCount,
            "the counter a device reports must exceed the one the server stored");

        // WRITTEN BACK BY THE SERVER. Persisting this is the backend job, not the library.
        storedRecord.SignCount = operation.NewSignCount;
        Assert.Equal(1u, storedRecord.SignCount);

        // Control A -- the same message replayed. It carries a real signature over real
        // material and must still be refused, because the stored counter no longer moves.
        // This is the one rejection a per-step test cannot demonstrate: it needs the state
        // the accepted call just wrote.
        AssertionResult replay = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            clientDataHashComputedByTheServer,
            storedRecord.PublicKeyDer,
            storedRecord.SignCount);

        Assert.False(replay.IsValid, "a replayed operation must not be accepted");
        Assert.Equal(AttestationFailureReason.SignCountNotIncreased, replay.Reason);

        // Control B -- the signature is bound to the request, not merely to the key. One byte
        // of the request body changes and nothing else does.
        byte[] tamperedBody = (byte[])operationFromTheApp.RequestBody.Clone();
        tamperedBody[^1] ^= 0xFF;

        AssertionResult tampered = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            AssertionBuilder.Sha256(tamperedBody, nonceIssuedByTheServer),
            storedRecord.PublicKeyDer,
            lastSignCount: 0);

        Assert.False(tampered.IsValid, "an operation whose body changed must not be accepted");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, tampered.Reason);

        // Control C -- the stored key is the one that decides. Another device record, with
        // this device message, is refused.
        AssertionResult strangersRecord = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            clientDataHashComputedByTheServer,
            AssertionBuilder.PublicKeyDer(AssertionBuilder.GenerateKeyPair().Public),
            lastSignCount: 0);

        Assert.False(strangersRecord.IsValid, "a message must not verify against another key");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, strangersRecord.Reason);
    }

    /// <summary>
    /// The nonce-signed operation on its own: what a backend runs on every request after
    /// enrollment, and the proof that the nonce it issued is what the signature covers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The flow test above shows this step in its place, joined to enrollment and to the
    /// counter. This one isolates the mechanism, because the question it answers is different:
    /// <b>does the nonce actually bind?</b> A verifier that ignored the nonce entirely would
    /// pass every assertion in the flow test, since that test only ever offers the right one.
    /// </para>
    /// <para>
    /// Each rejection below changes exactly one thing and leaves the rest as the accepted call
    /// had it, so the refusal names its own cause. The counter is deliberately not exercised
    /// here -- replay by counter belongs to the flow test, which has the stored state it needs.
    /// </para>
    /// <para>
    /// <b>There is no Android counterpart to this test.</b> Not because it was skipped, but
    /// because the library has nothing to call: <see cref="IAssertionVerifier"/> is implemented
    /// for Apple alone. See the remarks on this class.
    /// </para>
    /// </remarks>
    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task Flow_AppleDevice_NonceBinding_OnlyTheIssuedNonceVerifies()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        // The device is already enrolled; this is the record read back out of storage.
        EnrolledDevice storedRecord = EnrolledDevice.From(await EnrollApple());

        AppleAssertionVerifier assertionVerifier = new AppleAssertionVerifier(storedRecord.AppId);

        // ISSUED BY THE SERVER, for this operation.
        byte[] nonceIssuedByTheServer = vector.AssertionNonce;

        // FROM THE APP.
        AppleOperation operationFromTheApp = new AppleOperation(
            AssertionObject: vector.AssertionObject,
            RequestBody: vector.AssertionRequestBody);

        // Accepted: the nonce the server issued, the body the app sent, the key it stored.
        AssertionResult accepted = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            AssertionBuilder.Sha256(operationFromTheApp.RequestBody, nonceIssuedByTheServer),
            storedRecord.PublicKeyDer,
            lastSignCount: 0);

        Assert.True(accepted.IsValid, $"the signed operation was refused with {accepted.Reason}");

        // ---- Rejection 1: a nonce the server really did issue, but for another step.
        //
        // This is the assertion the whole test exists for. The attestation challenge is a
        // genuine server-issued value from the enrollment step, and it is measurably not this
        // operation nonce -- so a verifier that skipped the nonce would still accept here.
        Assert.NotEqual(vector.AttestationChallenge, nonceIssuedByTheServer);

        AssertionResult otherNonce = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            AssertionBuilder.Sha256(operationFromTheApp.RequestBody, vector.AttestationChallenge),
            storedRecord.PublicKeyDer,
            lastSignCount: 0);

        Assert.False(otherNonce.IsValid, "a signature must not verify under a different nonce");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, otherNonce.Reason);

        // ---- Rejection 2: the right nonce, a changed request. The signature is bound to what
        // was asked for, not merely to the fact that something was asked.
        byte[] tamperedBody = (byte[])operationFromTheApp.RequestBody.Clone();
        tamperedBody[^1] ^= 0xFF;

        AssertionResult tamperedRequest = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            AssertionBuilder.Sha256(tamperedBody, nonceIssuedByTheServer),
            storedRecord.PublicKeyDer,
            lastSignCount: 0);

        Assert.False(tamperedRequest.IsValid, "a changed request must not verify");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, tamperedRequest.Reason);

        // ---- Rejection 3: a key that was never enrolled. The stored record decides, and one
        // device operation cannot be accepted under another device record.
        AssertionResult strangersKey = await assertionVerifier.VerifyAsync(
            operationFromTheApp.AssertionObject,
            AssertionBuilder.Sha256(operationFromTheApp.RequestBody, nonceIssuedByTheServer),
            AssertionBuilder.PublicKeyDer(AssertionBuilder.GenerateKeyPair().Public),
            lastSignCount: 0);

        Assert.False(strangersKey.IsValid, "an operation must not verify against an unenrolled key");
        Assert.Equal(AttestationFailureReason.SignatureInvalid, strangersKey.Reason);
    }

    // ========================================================================= Android

    [FixtureFact(
        TestVectors.AndroidLeafPath,
        TestVectors.AndroidIntermediatePath,
        TestVectors.AndroidAnchorPath)]
    public async Task Flow_AndroidDevice_Enroll_EndsAtEnrollmentAndSaysSo()
    {
        X509Certificate leaf = LoadCertificate(TestVectors.AndroidLeafPath);
        X509Certificate intermediate = LoadCertificate(TestVectors.AndroidIntermediatePath);
        X509Certificate anchor = LoadCertificate(TestVectors.AndroidAnchorPath);

        // The record inside the leaf is what the device attested. The challenge and the
        // signing digest are read out of it rather than written down here, so that no real
        // application identity enters this repository and the test follows the vector when
        // the vector changes.
        Assert.True(
            KeyDescription.TryReadFrom(leaf, out KeyDescription? record, out AttestationFailureReason reason),
            $"the device leaf carried no attestation record: {reason}");

        AttestationApplicationId application = record!.SoftwareEnforced.AttestationApplicationId!;

        // --------------------------------------------------------------------------------
        // HELD ON THE SERVER, before any device talks to it.
        // --------------------------------------------------------------------------------
        AndroidAttestOptions heldOnTheServer = new AndroidAttestOptions
        {
            // Which application builds are acceptable. In a deployment this is a constant in
            // configuration; here it is read from the capture for the reason above.
            AllowedSignatureDigests =
                new[] { Convert.ToHexString(application.SignatureDigests[0].ToArray()) },

            // Measured: this device attests at TrustedEnvironment. A deployment demanding
            // StrongBox refuses it, which the per-step tests cover.
            RequireStrongBox = false,

            // The highest certificate this capture contains is an intermediate, not a Google
            // root. Pinning it is what lets the chain validate here, and it is the limit of
            // what this vector shows: it does not demonstrate a chain reaching a genuine
            // platform root.
            PinnedRootCertificates = new[] { anchor },

            // A deployment must choose; there is no default. Revocation itself is examined by
            // KeyStatusTests, not here -- Skip with no status source means the check does not
            // run, which is the caller saying so out loud.
            RevocationPolicy = RevocationPolicy.Skip,
        };

        // ISSUED BY THE SERVER.
        byte[] challengeIssuedByTheServer = record.AttestationChallenge.ToArray();

        // FROM THE APP -- on Android the entire enrollment message is the chain.
        AndroidEnrollment fromTheApp = new AndroidEnrollment(
            new[] { leaf.GetEncoded(), intermediate.GetEncoded() });

        AttestationResult enrollment =
            await new AndroidKeyAttestationVerifier(heldOnTheServer, AndroidEnrollmentTime)
                .VerifyAsync(new AndroidAttestationRequest(
                    fromTheApp.AsRequestChain(),
                    challengeIssuedByTheServer));

        Assert.True(enrollment.IsValid, $"enrollment was refused with {enrollment.Reason}");
        Assert.Equal(Platform.Android, enrollment.Platform);

        // --------------------------------------------------------------------------------
        // STORED BY THE SERVER.
        // --------------------------------------------------------------------------------
        EnrolledDevice storedRecord = EnrolledDevice.From(enrollment);

        Assert.Equal(32, storedRecord.KeyId.Length);
        Assert.NotEmpty(storedRecord.PublicKeyDer);
        Assert.Equal(application.PackageInfos[0].PackageName, storedRecord.AppId);

        // Android key attestation carries no environment marker of the kind the Apple AAGUID
        // gives. The field is left unknown rather than filled with a guess.
        Assert.Equal(AttestationEnvironment.Unknown, storedRecord.Environment);

        // --------------------------------------------------------------------------------
        // AND THE FLOW ENDS HERE. There is no counter to advance and no receipt to keep, so
        // an Android record is strictly smaller than an Apple one. A deployment needing
        // per-operation proof on Android builds that itself; this library verifies the
        // enrollment and stops.
        // --------------------------------------------------------------------------------
        Assert.Equal(0u, storedRecord.SignCount);
        Assert.Empty(storedRecord.Receipt);

        // Control -- the challenge binding. The same chain, offered against a challenge the
        // server did not issue for it, is refused. Without this, the acceptance above would
        // also be produced by a verifier that ignores the challenge entirely.
        byte[] challengeTheServerNeverIssued = (byte[])challengeIssuedByTheServer.Clone();
        challengeTheServerNeverIssued[0] ^= 0xFF;

        AttestationResult wrongChallenge =
            await new AndroidKeyAttestationVerifier(heldOnTheServer, AndroidEnrollmentTime)
                .VerifyAsync(new AndroidAttestationRequest(
                    fromTheApp.AsRequestChain(),
                    challengeTheServerNeverIssued));

        Assert.False(wrongChallenge.IsValid);
        Assert.Equal(AttestationFailureReason.ChallengeMismatch, wrongChallenge.Reason);
    }

    // ==================================================================== both at once

    [FixtureFact(
        TestVectors.AppleVectorPath,
        TestVectors.AppleRootPath,
        TestVectors.AndroidLeafPath,
        TestVectors.AndroidIntermediatePath,
        TestVectors.AndroidAnchorPath)]
    public async Task Flow_BothPlatforms_EnrollIntoTheSameShapeOfRecord()
    {
        EnrolledDevice apple = EnrolledDevice.From(await EnrollApple());
        EnrolledDevice android = EnrolledDevice.From(await EnrollAndroid());

        // The claim the library makes -- two platforms, two mechanisms, one result type --
        // checked on real material from both rather than asserted in a document. A backend
        // storing enrollments in one table needs exactly these fields present and comparable
        // on both sides, and this is the list to build that table from.
        foreach (EnrolledDevice storedRecord in new[] { apple, android })
        {
            Assert.Equal(32, storedRecord.KeyId.Length);
            Assert.NotEmpty(storedRecord.PublicKeyDer);
            Assert.False(string.IsNullOrEmpty(storedRecord.AppId));
            Assert.Equal(0u, storedRecord.SignCount);
        }

        Assert.Equal(Platform.Apple, apple.Platform);
        Assert.Equal(Platform.Android, android.Platform);

        // Two devices, two key identifiers. The identifier is over the attested public key,
        // so this also says the two enrollments did not collapse into one record.
        Assert.NotEqual(apple.KeyId, android.KeyId);

        // The shape is shared; the contents are not. Only the Apple side carries a receipt,
        // and only the Apple side reports an environment -- so a column that is mandatory for
        // one platform is empty for the other, by design rather than by omission.
        Assert.NotEmpty(apple.Receipt);
        Assert.Empty(android.Receipt);
        Assert.Equal(AttestationEnvironment.Development, apple.Environment);
        Assert.Equal(AttestationEnvironment.Unknown, android.Environment);
    }

    // ===================================================================== trust anchors

    /// <summary>
    /// The trust anchors half of "held on the server": which roots a deployment pins, where
    /// they are obtained, and the check that says the file on disk is still the right one.
    /// </summary>
    /// <remarks>
    /// <para><b>A root is never taken from the chain the device sent.</b></para>
    /// <para>
    /// That would be circular: whoever forges a chain supplies its root along with it. An
    /// anchor has to arrive out of band, from the platform vendor, and be pinned. The value of
    /// checking a device chain against a pinned root comes entirely from the root having been
    /// obtained independently first.
    /// </para>
    /// <para><b>Where they come from</b></para>
    /// <list type="bullet">
    ///   <item><description>
    ///   Apple publishes one App Attest anchor as a single PEM file, on its certificate
    ///   authority page. It carries no published fingerprint, so the constants below are the
    ///   deployment own control rather than a copy of a vendor value.
    ///   </description></item>
    ///   <item><description>
    ///   Google publishes its anchors as a machine-readable JSON array at
    ///   <c>android.googleapis.com/attestation/root</c>. Measured when these constants were
    ///   written: the active set holds exactly two, and both are pinned here. Google
    ///   documentation additionally lists previously issued roots that the active set does not
    ///   contain.
    ///   </description></item>
    /// </list>
    /// <para><b>Consequences a deployment has to plan for</b></para>
    /// <para>
    /// Two Google anchors, not one: pinning only the older root refuses devices whose chains
    /// reach the newer one. And the set is published rather than fixed, so refreshing it is an
    /// owned operational task, done at deployment time. This library reaches no network of its
    /// own, and that does not change: the refreshed set arrives as configuration.
    /// </para>
    /// <para>
    /// The digests below are what makes a downloaded file acceptable. A file is trusted
    /// because it hashes to a value written down in advance, not because of where it was
    /// fetched from -- and this test fails if a root on disk is swapped, truncated or quietly
    /// replaced by a newer issue.
    /// </para>
    /// </remarks>
    [FixtureFact(
        TestVectors.AppleRootPath,
        TestVectors.AndroidRoot2022Path,
        TestVectors.AndroidRootKeyAttestationCa1Path)]
    public void TrustAnchors_HeldOnTheServer_AreTheRootsTheyClaimToBe()
    {
        // Apple App Attestation Root CA, valid 2020-03-18 to 2045-03-15.
        AssertAnchor(
            TestVectors.AppleRootPath,
            "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932",
            "CN=Apple App Attestation Root CA,O=Apple Inc.,ST=California");

        // Google hardware attestation root, valid 2022-03-20 to 2042-03-15. This is the anchor
        // the SIMA device chain was measured to reach.
        AssertAnchor(
            TestVectors.AndroidRoot2022Path,
            "CEDB1CB6DC896AE5EC797348BCE9286753C2B38EE71CE0FBE34A9A1248800DFC",
            "SERIALNUMBER=f92009e853b6b045");

        // Google Key Attestation CA1, valid 2025-07-17 to 2035-07-15.
        AssertAnchor(
            TestVectors.AndroidRootKeyAttestationCa1Path,
            "6D9DB4CE6C5C0B293166D08986E05774A8776CEB525D9E4329520DE12BA4BCC0",
            "CN=Key Attestation CA1,OU=Android,O=Google LLC,C=US");

        // The Android side pins two anchors, and they are genuinely different certificates.
        // A deployment that kept only one would still pass every assertion above, so the
        // distinctness is asserted rather than assumed.
        X509Certificate older = LoadCertificate(TestVectors.AndroidRoot2022Path);
        X509Certificate newer = LoadCertificate(TestVectors.AndroidRootKeyAttestationCa1Path);

        Assert.NotEqual(older.GetEncoded(), newer.GetEncoded());
        Assert.False(
            older.SubjectDN.Equivalent(newer.SubjectDN, true),
            "the two Google anchors are expected to be distinct issuers");
    }

    /// <summary>
    /// Checks one anchor: it hashes to the digest written down in advance, it names the
    /// subject expected of it, and it is self-signed rather than a link out of some chain.
    /// </summary>
    private static void AssertAnchor(string relativePath, string expectedSha256, string expectedSubject)
    {
        X509Certificate anchor = LoadCertificate(relativePath);

        Assert.Equal(expectedSha256, Convert.ToHexString(AssertionBuilder.Sha256(anchor.GetEncoded())));
        Assert.Equal(expectedSubject, anchor.SubjectDN.ToString());

        // An anchor issues itself. Anything else is an intermediate, and pinning one narrows
        // trust to a single branch that the vendor may retire without notice.
        Assert.True(
            anchor.SubjectDN.Equivalent(anchor.IssuerDN, true),
            $"{relativePath} is expected to be self-signed");
    }

    // ================================================================ wire message types

    /// <summary>
    /// The iOS enrollment message: everything the app sends, and nothing else.
    /// </summary>
    /// <remarks>
    /// It exists so that "this came from the device" is carried by the type rather than by a
    /// comment. A value that is not in here did not cross the wire, and a reader building the
    /// endpoint can take these fields as the request body.
    /// </remarks>
    private sealed record AppleEnrollment(byte[] KeyId, byte[] AttestationObject);

    /// <summary>The iOS per-operation message: the signed blob and the request it covers.</summary>
    /// <remarks>
    /// The client data hash is deliberately absent. The server computes it from this request
    /// body and the nonce it issued; accepting it from the app would let the app choose what
    /// its own signature is checked against.
    /// </remarks>
    private sealed record AppleOperation(byte[] AssertionObject, byte[] RequestBody);

    /// <summary>
    /// The Android enrollment message: the certificate chain, leaf first.
    /// </summary>
    /// <remarks>
    /// There is no Android counterpart to <see cref="AppleOperation"/>, and that absence is
    /// the contract rather than an oversight -- see the remarks on this class.
    /// </remarks>
    private sealed record AndroidEnrollment(IReadOnlyList<byte[]> CertificateChain)
    {
        /// <summary>Presents the chain in the shape the request type takes.</summary>
        public IReadOnlyList<ReadOnlyMemory<byte>> AsRequestChain() =>
            CertificateChain.Select(der => (ReadOnlyMemory<byte>)der).ToArray();
    }

    // ============================================================================ helpers

    private static async Task<AttestationResult> EnrollApple()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        AppleAttestOptions heldOnTheServer = new AppleAttestOptions
        {
            TeamId = vector.TeamId,
            BundleIdAllowlist = new[] { vector.BundleId },
            RequireProduction = false,
            PinnedRootCertificates = new[] { LoadCertificate(TestVectors.AppleRootPath) },
        };

        AttestationResult result = await new AppleAppAttestVerifier(heldOnTheServer).VerifyAsync(
            new AppleAttestationRequest(
                Convert.FromBase64String(vector.KeyIdBase64),
                vector.AttestationObject,
                vector.AttestationChallenge),
            AppleEnrollmentTime);

        Assert.True(result.IsValid, $"Apple enrollment was refused with {result.Reason}");
        return result;
    }

    private static async Task<AttestationResult> EnrollAndroid()
    {
        X509Certificate leaf = LoadCertificate(TestVectors.AndroidLeafPath);
        X509Certificate intermediate = LoadCertificate(TestVectors.AndroidIntermediatePath);

        Assert.True(KeyDescription.TryReadFrom(leaf, out KeyDescription? record, out _));

        AttestationApplicationId application = record!.SoftwareEnforced.AttestationApplicationId!;

        AndroidAttestOptions heldOnTheServer = new AndroidAttestOptions
        {
            AllowedSignatureDigests =
                new[] { Convert.ToHexString(application.SignatureDigests[0].ToArray()) },
            RequireStrongBox = false,
            PinnedRootCertificates = new[] { LoadCertificate(TestVectors.AndroidAnchorPath) },
            RevocationPolicy = RevocationPolicy.Skip,
        };

        AttestationResult result =
            await new AndroidKeyAttestationVerifier(heldOnTheServer, AndroidEnrollmentTime).VerifyAsync(
                new AndroidAttestationRequest(
                    new ReadOnlyMemory<byte>[] { leaf.GetEncoded(), intermediate.GetEncoded() },
                    record.AttestationChallenge.ToArray()));

        Assert.True(result.IsValid, $"Android enrollment was refused with {result.Reason}");
        return result;
    }

    private static X509Certificate LoadCertificate(string relativePath) =>
        PemRootStore.LoadFromPem(File.ReadAllText(TestVectors.Resolve(relativePath)))[0];

    /// <summary>
    /// What the backend stores after a successful enrollment, and reads back on every later
    /// operation. These fields are the database columns.
    /// </summary>
    /// <remarks>
    /// Nothing in here is taken from the app message or from the vector -- every field comes
    /// out of the <see cref="AttestationResult"/> the library returned, which is what makes
    /// the later operation a genuine test of the join between the two verifiers.
    /// <para>
    /// It is a class rather than a record because the counter is mutable state: the server
    /// advances it on every accepted operation, and the replay control depends on that having
    /// happened.
    /// </para>
    /// </remarks>
    private sealed class EnrolledDevice
    {
        private EnrolledDevice(
            Platform platform,
            AttestationEnvironment environment,
            byte[] keyId,
            byte[] publicKeyDer,
            string appId,
            uint signCount,
            byte[] receipt)
        {
            Platform = platform;
            Environment = environment;
            KeyId = keyId;
            PublicKeyDer = publicKeyDer;
            AppId = appId;
            SignCount = signCount;
            Receipt = receipt;
        }

        /// <summary>Which mechanism enrolled this device.</summary>
        public Platform Platform { get; }

        /// <summary>Development or production, where the platform reports it.</summary>
        public AttestationEnvironment Environment { get; }

        /// <summary>The lookup key: 32 bytes over the attested public key.</summary>
        public byte[] KeyId { get; }

        /// <summary>The attested public key, and the only key later operations verify against.</summary>
        public byte[] PublicKeyDer { get; }

        /// <summary>The application identity the platform vouched for.</summary>
        public string AppId { get; }

        /// <summary>The counter, advanced only when an accepted operation reports a higher one.</summary>
        public uint SignCount { get; set; }

        /// <summary>Apple only, and opaque to this library.</summary>
        public byte[] Receipt { get; }

        public static EnrolledDevice From(AttestationResult result)
        {
            Assert.True(result.IsValid, "only a valid attestation is stored");
            Assert.NotNull(result.AppId);

            return new EnrolledDevice(
                result.Platform,
                result.Environment,
                result.KeyId.ToArray(),
                result.PublicKeyDer.ToArray(),
                result.AppId!,
                result.SignCount,
                result.Receipt.ToArray());
        }
    }
}
