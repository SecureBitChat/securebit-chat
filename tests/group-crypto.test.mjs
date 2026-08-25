// Group cryptography: the safety code, membership operations and message
// signatures.
//
// The assertions that matter most are the ones about ORDER. A group safety code
// of seven digits is only safe because no member can reveal their nonce before
// every commitment is in — otherwise a member who introduces two others can
// grind their own keys until both victims see the same digits. That gate is
// asserted directly here, not inferred from the code shape, and so is the
// mismatch a real man-in-the-middle would produce.

import assert from 'node:assert/strict';

const {
    GROUP_LIMITS,
    MEMBER_OPS,
    GroupSasCeremony,
    generateGroupIdentity,
    fingerprintSpki,
    importMemberIdentity,
    buildCommitment,
    verifyCommitment,
    computeGroupSas,
    canonicalFingerprints,
    memberOpPayload,
    signMemberOp,
    verifyMemberOp,
    hashBody,
    signGroupMessage,
    verifyGroupMessage,
    newGroupId,
    randomBytes,
    toHex,
    fromHex,
    toB64,
    fromB64,
} = await import('../src/group/groupCrypto.js');

const subtle = crypto.subtle;
const GID = newGroupId();

// ---------------------------------------------------------------------------
// identity keys
// ---------------------------------------------------------------------------
{
    const alice = await generateGroupIdentity(subtle);
    assert.equal(alice.fingerprint.length, 64, 'a fingerprint is SHA-256 in hex');
    assert.equal(alice.keyPair.privateKey.extractable, false, 'the signing key must not be extractable');

    // The fingerprint a peer computes from the published bytes must equal ours.
    const imported = await importMemberIdentity(subtle, alice.spki);
    assert.equal(imported.fingerprint, alice.fingerprint, 'both sides must name a member identically');

    // A member is named by what their key hashes to, never by what they claim.
    const bob = await generateGroupIdentity(subtle);
    assert.notEqual(bob.fingerprint, alice.fingerprint);

    // Garbage SPKI is refused rather than producing a usable member.
    await assert.rejects(
        () => importMemberIdentity(subtle, new Uint8Array(120).fill(7)),
        /valid P-384 public key/,
    );
    await assert.rejects(
        () => fingerprintSpki(subtle, new Uint8Array(8)),
        /SPKI length out of range/,
    );
}

// ---------------------------------------------------------------------------
// commitments
// ---------------------------------------------------------------------------
{
    const fp = toHex(randomBytes(32));
    const nonce = randomBytes(32);
    const fields = { groupId: GID, epoch: 1, fingerprint: fp, nonce };
    const commitment = await buildCommitment(subtle, fields);

    assert.equal(commitment.length, GROUP_LIMITS.COMMIT_BYTES);
    assert.equal(await verifyCommitment(subtle, commitment, fields), true);

    // Every bound field is really bound.
    assert.equal(await verifyCommitment(subtle, commitment, { ...fields, epoch: 2 }), false, 'epoch is bound');
    assert.equal(await verifyCommitment(subtle, commitment, { ...fields, groupId: newGroupId() }), false, 'group id is bound');
    assert.equal(await verifyCommitment(subtle, commitment, { ...fields, fingerprint: toHex(randomBytes(32)) }), false, 'member is bound');
    assert.equal(await verifyCommitment(subtle, commitment, { ...fields, nonce: randomBytes(32) }), false, 'nonce is bound');

    // Malformed input returns false rather than throwing into the caller.
    assert.equal(await verifyCommitment(subtle, new Uint8Array(4), fields), false);
    await assert.rejects(() => buildCommitment(subtle, { ...fields, nonce: randomBytes(8) }), /nonce must be 32 bytes/);
}

// ---------------------------------------------------------------------------
// the ordering gate — the reason seven digits is enough
// ---------------------------------------------------------------------------
{
    const [a, b, c] = await Promise.all([
        generateGroupIdentity(subtle), generateGroupIdentity(subtle), generateGroupIdentity(subtle),
    ]);
    const members = [a.fingerprint, b.fingerprint, c.fingerprint];
    const ceremony = new GroupSasCeremony({
        groupId: GID, epoch: 1, selfFingerprint: a.fingerprint, memberFingerprints: members,
    });

    await ceremony.ownCommitment(subtle);
    assert.equal(ceremony.commitmentsComplete, false);

    // THE gate: no nonce leaves this device while a commitment is outstanding.
    assert.throws(() => ceremony.reveal(), /cannot reveal before every member has committed/);

    const bCeremony = new GroupSasCeremony({
        groupId: GID, epoch: 1, selfFingerprint: b.fingerprint, memberFingerprints: members,
    });
    ceremony.acceptCommitment(b.fingerprint, await bCeremony.ownCommitment(subtle));
    assert.throws(() => ceremony.reveal(), /cannot reveal/, 'two of three is still not all');

    const cCeremony = new GroupSasCeremony({
        groupId: GID, epoch: 1, selfFingerprint: c.fingerprint, memberFingerprints: members,
    });
    ceremony.acceptCommitment(c.fingerprint, await cCeremony.ownCommitment(subtle));
    assert.equal(ceremony.commitmentsComplete, true);
    assert.doesNotThrow(() => ceremony.reveal(), 'a complete commitment round unlocks the reveal');

    // A member may not move after committing.
    const other = new GroupSasCeremony({
        groupId: GID, epoch: 1, selfFingerprint: b.fingerprint, memberFingerprints: members,
    });
    assert.throws(
        () => ceremony.acceptCommitment(b.fingerprint, new Uint8Array(32).fill(9)),
        /member changed their commitment/,
    );
    void other;

    // Outsiders are refused outright.
    assert.throws(
        () => ceremony.acceptCommitment(toHex(randomBytes(32)), new Uint8Array(32)),
        /commitment from a non-member/,
    );

    // A nonce that does not open its commitment fails the ceremony.
    await assert.rejects(
        () => ceremony.acceptReveal(subtle, b.fingerprint, randomBytes(32)),
        /does not match the commitment/,
    );
}

// ---------------------------------------------------------------------------
// an honest group converges on one code
// ---------------------------------------------------------------------------

/** Run a full commit -> reveal -> finish round between n honest members. */
async function honestCeremony(identities, { groupId = GID, epoch = 1 } = {}) {
    const members = identities.map((i) => i.fingerprint);
    const ceremonies = identities.map((i) => new GroupSasCeremony({
        groupId, epoch, selfFingerprint: i.fingerprint, memberFingerprints: members,
    }));

    const commitments = [];
    for (const c of ceremonies) commitments.push(await c.ownCommitment(subtle));
    for (let i = 0; i < ceremonies.length; i++) {
        for (let j = 0; j < ceremonies.length; j++) {
            if (i !== j) ceremonies[i].acceptCommitment(members[j], commitments[j]);
        }
    }

    const nonces = ceremonies.map((c) => c.reveal());
    for (let i = 0; i < ceremonies.length; i++) {
        for (let j = 0; j < ceremonies.length; j++) {
            if (i !== j) await ceremonies[i].acceptReveal(subtle, members[j], nonces[j]);
        }
    }
    return Promise.all(ceremonies.map((c) => c.finish(subtle)));
}

{
    const identities = await Promise.all(
        Array.from({ length: 5 }, () => generateGroupIdentity(subtle)),
    );
    const codes = await honestCeremony(identities);
    assert.equal(new Set(codes).size, 1, 'every honest member must read the same digits');
    assert.match(codes[0], /^\d{7}$/, 'the group code is seven digits, like the pairwise SAS');
}

// ---------------------------------------------------------------------------
// a man in the middle produces a MISMATCH — which is the whole point
// ---------------------------------------------------------------------------
{
    // Bob and Carol are introduced by Mallory, who presents a different key to
    // each of them. Neither can detect that from their own view alone; the group
    // code is what differs when they compare it out loud.
    const bob = await generateGroupIdentity(subtle);
    const carol = await generateGroupIdentity(subtle);
    const malloryToBob = await generateGroupIdentity(subtle);
    const malloryToCarol = await generateGroupIdentity(subtle);

    const bobsView = await honestCeremony([bob, carol, malloryToBob]);
    const carolsView = await honestCeremony([bob, carol, malloryToCarol]);

    assert.notEqual(
        bobsView[0], carolsView[0],
        'substituted key material must change the digits the victims read',
    );
}

// ---------------------------------------------------------------------------
// the code does not depend on the order members were listed in
// ---------------------------------------------------------------------------
{
    const fps = Array.from({ length: 4 }, () => toHex(randomBytes(32)));
    const contributions = fps.map((fingerprint) => ({ fingerprint, nonce: randomBytes(32) }));

    const forward = await computeGroupSas(subtle, { groupId: GID, epoch: 3, contributions });
    const reversed = await computeGroupSas(subtle, { groupId: GID, epoch: 3, contributions: [...contributions].reverse() });
    assert.equal(forward, reversed, 'member ordering must not change the code');

    // But the epoch and the group do.
    const nextEpoch = await computeGroupSas(subtle, { groupId: GID, epoch: 4, contributions });
    assert.notEqual(forward, nextEpoch, 'a new epoch must produce a new code');
    const otherGroup = await computeGroupSas(subtle, { groupId: newGroupId(), epoch: 3, contributions });
    assert.notEqual(forward, otherGroup, 'the code is bound to the group');

    // canonicalFingerprints is where the ordering and the limits are enforced.
    assert.deepEqual(canonicalFingerprints([...fps].reverse()), [...fps].sort());
    assert.throws(() => canonicalFingerprints([fps[0], fps[0]]), /duplicate member/);
    assert.throws(() => canonicalFingerprints([fps[0]]), /at least two members/);
    assert.throws(
        () => canonicalFingerprints(Array.from({ length: 9 }, () => toHex(randomBytes(32)))),
        /limited to 8 members/,
    );
}

// ---------------------------------------------------------------------------
// membership operations
// ---------------------------------------------------------------------------
{
    const admin = await generateGroupIdentity(subtle);
    const bob = await generateGroupIdentity(subtle);
    const carol = await generateGroupIdentity(subtle);
    const { publicKey: adminKey } = await importMemberIdentity(subtle, admin.spki);

    const fields = {
        groupId: GID, epoch: 2, op: MEMBER_OPS.ADD,
        memberFps: [admin.fingerprint, bob.fingerprint, carol.fingerprint],
        name: 'Field team',
    };
    const sig = await signMemberOp(subtle, admin.keyPair.privateKey, fields);
    assert.equal(await verifyMemberOp(subtle, adminKey, fields, sig), true);

    // Every signed field is bound.
    assert.equal(await verifyMemberOp(subtle, adminKey, { ...fields, epoch: 3 }, sig), false, 'epoch is signed');
    assert.equal(await verifyMemberOp(subtle, adminKey, { ...fields, op: MEMBER_OPS.REMOVE }, sig), false, 'the operation is signed');
    assert.equal(await verifyMemberOp(subtle, adminKey, { ...fields, name: 'Field teams' }, sig), false, 'the name is signed');
    assert.equal(
        await verifyMemberOp(subtle, adminKey, { ...fields, memberFps: [admin.fingerprint, bob.fingerprint] }, sig),
        false, 'dropping a member invalidates the operation',
    );
    assert.equal(await verifyMemberOp(subtle, adminKey, { ...fields, groupId: newGroupId() }, sig), false, 'the group is signed');

    // Someone else's key does not verify the admin's operation.
    const { publicKey: bobKey } = await importMemberIdentity(subtle, bob.spki);
    assert.equal(await verifyMemberOp(subtle, bobKey, fields, sig), false, 'only the admin can author membership');

    // Reordering the member list is NOT a different operation — canonical order.
    const shuffled = { ...fields, memberFps: [carol.fingerprint, admin.fingerprint, bob.fingerprint] };
    assert.equal(await verifyMemberOp(subtle, adminKey, shuffled, sig), true, 'member order is canonicalised before signing');

    // Malformed signatures are rejected without throwing.
    assert.equal(await verifyMemberOp(subtle, adminKey, fields, new Uint8Array(4)), false);
    assert.equal(await verifyMemberOp(subtle, adminKey, fields, 'not bytes'), false);

    // Length-prefixed encoding: no two field sets can collide.
    const a = memberOpPayload({ ...fields, name: 'ab' });
    const b = memberOpPayload({ ...fields, name: 'a' });
    assert.notEqual(toHex(a), toHex(b));
}

// ---------------------------------------------------------------------------
// group message signatures
// ---------------------------------------------------------------------------
{
    const sender = await generateGroupIdentity(subtle);
    const { publicKey } = await importMemberIdentity(subtle, sender.spki);

    const body = 'meet at the usual place';
    const bodyHash = await hashBody(subtle, body);
    const fields = { groupId: GID, epoch: 1, seq: 7, senderFp: sender.fingerprint, bodyHash };
    const sig = await signGroupMessage(subtle, sender.keyPair.privateKey, fields);

    assert.equal(await verifyGroupMessage(subtle, publicKey, fields, sig), true);

    // A different body under the same signature is what a tampering relay would
    // have to produce, and it does not verify.
    const otherHash = await hashBody(subtle, 'meet at the other place');
    assert.equal(await verifyGroupMessage(subtle, publicKey, { ...fields, bodyHash: otherHash }, sig), false);

    // Replaying one message under another sequence number or epoch fails too.
    assert.equal(await verifyGroupMessage(subtle, publicKey, { ...fields, seq: 8 }, sig), false, 'seq is signed');
    assert.equal(await verifyGroupMessage(subtle, publicKey, { ...fields, epoch: 2 }, sig), false, 'epoch is signed');
    assert.equal(await verifyGroupMessage(subtle, publicKey, { ...fields, senderFp: toHex(randomBytes(32)) }, sig), false);

    // Oversized bodies are refused before they are hashed.
    await assert.rejects(
        () => hashBody(subtle, 'x'.repeat(GROUP_LIMITS.MAX_BODY_BYTES + 1)),
        /exceeds the group limit/,
    );
}

// ---------------------------------------------------------------------------
// codecs bound their input
// ---------------------------------------------------------------------------
{
    const bytes = randomBytes(48);
    assert.equal(toHex(fromHex(toHex(bytes))), toHex(bytes));
    assert.deepEqual(fromB64(toB64(bytes)), bytes);

    assert.throws(() => fromHex('zz'), /not a hex string/);
    assert.throws(() => fromHex('abc'), /not a hex string/);
    // The base64 bound is applied before decoding, so a huge string cannot force
    // a huge allocation.
    assert.throws(() => fromB64('A'.repeat(100000)), /exceeds its limit/);
    assert.throws(() => fromB64('!!!!', { max: 64 }), /malformed base64/);
}

console.log('group-crypto.test.mjs: all assertions passed');
