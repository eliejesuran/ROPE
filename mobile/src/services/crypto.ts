/**
 * ROPE Crypto — AES-256-GCM via node-forge (pure JS) + X3DH + Double Ratchet.
 *
 * globalThis.crypto.subtle is not reliably available in all React Native /
 * Hermes configurations. node-forge ships as a pure-JS library, requires no
 * native module, and is already a transitive dependency of the project.
 *
 * Ciphertext layout: base64(cipher_bytes ‖ 16-byte GCM auth tag)
 * This matches Web Crypto AES-GCM output so stored messages stay readable.
 */

import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import * as forge from 'node-forge';
import { x25519, ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import {
  aesGcmEncryptString, aesGcmDecryptString,
  uint8ArrayToBase64, u8ToBin, b64ToBin, binToB64, b64ToU8, concatU8,
  IV_SIZE, TAG_SIZE,
} from './aes';
import { getJSON, setJSON, deleteJSON, wipeSecureFiles } from './secureFiles';

export { b64ToU8 } from './aes';

const KEY_SIZE = 32; // 256 bits

// ── AES key generation ────────────────────────────────────────────────────────

export async function generateConversationKey(): Promise<string> {
  const keyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);
  return uint8ArrayToBase64(keyBytes);
}

// ── Secure random key helpers (expo-crypto avoids crypto.getRandomValues) ────

async function randomX25519PrivKey(): Promise<Uint8Array> {
  const bytes = await Crypto.getRandomBytesAsync(32);
  // Curve25519 clamping per RFC 7748
  bytes[0]  &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}

async function randomEd25519PrivKey(): Promise<Uint8Array> {
  return Crypto.getRandomBytesAsync(32);
}

// ── Device identity keys (X3DH / Curve25519) ─────────────────────────────────

/**
 * Returns the device's X25519 identity keypair (IK), generating it on
 * first call. The returned publicKey is stored in users.public_key on the server.
 */
export async function getOrCreateDeviceKeypair(): Promise<{ publicKey: string }> {
  const existingPub = await SecureStore.getItemAsync('ik_pub');
  if (existingPub) return { publicKey: existingPub };

  const ikPriv  = await randomX25519PrivKey();
  const ikPub   = x25519.getPublicKey(ikPriv);
  const sigPriv = await randomEd25519PrivKey();
  const sigPub  = ed25519.getPublicKey(sigPriv);

  await SecureStore.setItemAsync('ik_priv',          uint8ArrayToBase64(ikPriv));
  await SecureStore.setItemAsync('ik_pub',           uint8ArrayToBase64(ikPub));
  await SecureStore.setItemAsync('ik_signing_priv',  uint8ArrayToBase64(sigPriv));
  await SecureStore.setItemAsync('ik_signing_pub',   uint8ArrayToBase64(sigPub));

  return { publicKey: uint8ArrayToBase64(ikPub) };
}

/**
 * Returns (or creates) the signed prekey (SPK).
 * The SPK is signed with the Ed25519 identity signing key so the recipient
 * can verify it wasn't tampered with.
 */
export async function getOrCreateSignedPreKey(): Promise<{
  spkPub:       string;
  spkSig:       string;
  spkId:        number;
  ikSigningPub: string;
}> {
  const existing = await SecureStore.getItemAsync('spk_pub');
  if (existing) {
    const spkId = parseInt((await SecureStore.getItemAsync('spk_id')) || '1');
    // Backfill the versioned copy (pre-rotation installs only have spk_priv)
    if (!(await SecureStore.getItemAsync(`spk_priv_${spkId}`))) {
      await SecureStore.setItemAsync(`spk_priv_${spkId}`, (await SecureStore.getItemAsync('spk_priv'))!);
      await SecureStore.setItemAsync(`spk_pub_${spkId}`,  existing);
    }
    return {
      spkPub:       existing,
      spkSig:       (await SecureStore.getItemAsync('spk_sig'))!,
      spkId,
      ikSigningPub: (await SecureStore.getItemAsync('ik_signing_pub'))!,
    };
  }

  const sigPriv = b64ToU8((await SecureStore.getItemAsync('ik_signing_priv'))!);
  const spkPriv = await randomX25519PrivKey();
  const spkPub  = x25519.getPublicKey(spkPriv);
  const spkSig  = ed25519.sign(spkPub, sigPriv);

  await SecureStore.setItemAsync('spk_priv', uint8ArrayToBase64(spkPriv));
  await SecureStore.setItemAsync('spk_pub',  uint8ArrayToBase64(spkPub));
  await SecureStore.setItemAsync('spk_sig',  uint8ArrayToBase64(spkSig));
  await SecureStore.setItemAsync('spk_id',   '1');
  // Versioned copy — kept across rotations so pending X3DH inits stay resolvable
  await SecureStore.setItemAsync('spk_priv_1', uint8ArrayToBase64(spkPriv));
  await SecureStore.setItemAsync('spk_pub_1',  uint8ArrayToBase64(spkPub));

  return {
    spkPub:       uint8ArrayToBase64(spkPub),
    spkSig:       uint8ArrayToBase64(spkSig),
    spkId:        1,
    ikSigningPub: (await SecureStore.getItemAsync('ik_signing_pub'))!,
  };
}

/**
 * Generates a new signed prekey (SPK), replacing the previous one.
 * Used for periodic SPK rotation (recommended every 7 days).
 */
export async function rotateSignedPreKey(): Promise<{
  spkPub: string; spkSig: string; spkId: number; ikSigningPub: string;
}> {
  const sigPriv = b64ToU8((await SecureStore.getItemAsync('ik_signing_priv'))!);
  const currentId = parseInt((await SecureStore.getItemAsync('spk_id')) || '1');
  const newId = currentId + 1;

  // Keep the outgoing SPK under its versioned key: an X3DH init posted against
  // it can still arrive — overwriting the private key would make that session
  // underivable (SK divergence). Backfill first for pre-rotation installs.
  const outgoingPriv = await SecureStore.getItemAsync('spk_priv');
  const outgoingPub  = await SecureStore.getItemAsync('spk_pub');
  if (outgoingPriv && outgoingPub && !(await SecureStore.getItemAsync(`spk_priv_${currentId}`))) {
    await SecureStore.setItemAsync(`spk_priv_${currentId}`, outgoingPriv);
    await SecureStore.setItemAsync(`spk_pub_${currentId}`,  outgoingPub);
  }

  const spkPriv = await randomX25519PrivKey();
  const spkPub  = x25519.getPublicKey(spkPriv);
  const spkSig  = ed25519.sign(spkPub, sigPriv);

  await SecureStore.setItemAsync('spk_priv', uint8ArrayToBase64(spkPriv));
  await SecureStore.setItemAsync('spk_pub',  uint8ArrayToBase64(spkPub));
  await SecureStore.setItemAsync('spk_sig',  uint8ArrayToBase64(spkSig));
  await SecureStore.setItemAsync('spk_id',   String(newId));
  await SecureStore.setItemAsync(`spk_priv_${newId}`, uint8ArrayToBase64(spkPriv));
  await SecureStore.setItemAsync(`spk_pub_${newId}`,  uint8ArrayToBase64(spkPub));

  // Prune copies older than 2 rotations (~3 weeks at the 7-day cadence) —
  // an init that stale must be re-established anyway
  const pruneId = newId - 3;
  if (pruneId >= 1) {
    await SecureStore.deleteItemAsync(`spk_priv_${pruneId}`);
    await SecureStore.deleteItemAsync(`spk_pub_${pruneId}`);
  }

  return {
    spkPub:       uint8ArrayToBase64(spkPub),
    spkSig:       uint8ArrayToBase64(spkSig),
    spkId:        newId,
    ikSigningPub: (await SecureStore.getItemAsync('ik_signing_pub'))!,
  };
}

/**
 * Generates `count` fresh one-time prekeys (OPKs) and stores their
 * private keys in SecureStore. Returns the public keys for server upload.
 */
export async function generateOneTimePreKeys(
  count: number
): Promise<Array<{ id: number; pub: string }>> {
  const raw   = await SecureStore.getItemAsync('opk_next_id');
  let nextId  = raw ? parseInt(raw) : 1;
  const keys: Array<{ id: number; pub: string }> = [];

  for (let i = 0; i < count; i++) {
    const priv = await randomX25519PrivKey();
    const pub  = x25519.getPublicKey(priv);
    const id   = nextId++;
    await SecureStore.setItemAsync(`opk_priv_${id}`, uint8ArrayToBase64(priv));
    keys.push({ id, pub: uint8ArrayToBase64(pub) });
  }

  await SecureStore.setItemAsync('opk_next_id', String(nextId));
  return keys;
}

// ── X3DH key agreement ────────────────────────────────────────────────────────

/**
 * X3DH initiator (Alice).
 * Fetches Bob's key bundle, verifies the SPK signature, performs the four
 * DH operations, derives the session key via HKDF, then immediately
 * initializes the Double Ratchet state as initiator.
 * Returns the ephemeral key and OPK ID that Bob needs to reproduce the SK.
 */
export async function x3dhInitiator(
  conversationId: string,
  theirBundle: {
    ikPub:        string;
    ikSigningPub: string;
    spkPub:       string;
    spkSig:       string;
    spkId:        number;
    opk:          { id: number; pub: string } | null;
  }
): Promise<{ ekPub: string; opkId: number | null; spkId: number }> {
  // Verify SPK signature — guards against server-side MITM
  const spkPubBytes    = b64ToU8(theirBundle.spkPub);
  const sigBytes       = b64ToU8(theirBundle.spkSig);
  const ikSignPubBytes = b64ToU8(theirBundle.ikSigningPub);
  if (!ed25519.verify(sigBytes, spkPubBytes, ikSignPubBytes)) {
    throw new Error('Invalid SPK signature — possible MITM attack');
  }

  const ikPriv  = b64ToU8((await SecureStore.getItemAsync('ik_priv'))!);
  const ekPriv  = await randomX25519PrivKey();
  const ekPub   = x25519.getPublicKey(ekPriv);
  const ikBPub  = b64ToU8(theirBundle.ikPub);
  const spkBPub = b64ToU8(theirBundle.spkPub);

  const dh1 = x25519.getSharedSecret(ikPriv, spkBPub);  // DH(IK_A, SPK_B)
  const dh2 = x25519.getSharedSecret(ekPriv, ikBPub);   // DH(EK_A, IK_B)
  const dh3 = x25519.getSharedSecret(ekPriv, spkBPub);  // DH(EK_A, SPK_B)

  const parts: Uint8Array[] = [new Uint8Array(32).fill(0xff), dh1, dh2, dh3];
  if (theirBundle.opk) {
    parts.push(x25519.getSharedSecret(ekPriv, b64ToU8(theirBundle.opk.pub)));
  }

  const sk = hkdf(sha256, concatU8(...parts), undefined, 'ROPE_X3DH_v1', KEY_SIZE);
  await storeConversationKey(conversationId, uint8ArrayToBase64(sk));
  // Pin the peer's identity key — a future mismatch means reinstall/new
  // device, and the session must be re-established (reset protocol)
  await setKnownPeerIk(conversationId, theirBundle.ikPub);

  // Initialize Double Ratchet as initiator — can send immediately
  await initDRAsInitiator(conversationId, sk, spkBPub);

  return {
    ekPub: uint8ArrayToBase64(ekPub),
    opkId: theirBundle.opk?.id ?? null,
    spkId: theirBundle.spkId,
  };
}

/**
 * X3DH responder (Bob).
 * Uses Alice's ephemeral key and the same DH operations (in reverse role)
 * to derive the identical session key, then initializes Double Ratchet as
 * responder. Bob must receive Alice's first message before he can send.
 */
export async function x3dhResponder(
  conversationId: string,
  initData: { ikPub: string; ekPub: string; opkId: number | null; spkId?: number | null }
): Promise<void> {
  const ikPriv = b64ToU8((await SecureStore.getItemAsync('ik_priv'))!);

  // Resolve the SPK the initiator actually used — a rotation may have
  // happened between the init being posted and us consuming it. Using the
  // wrong SPK would silently derive a different SK (broken session).
  let spkPrivStr: string | null;
  let spkPubStr:  string | null;
  if (initData.spkId != null) {
    spkPrivStr = await SecureStore.getItemAsync(`spk_priv_${initData.spkId}`);
    spkPubStr  = await SecureStore.getItemAsync(`spk_pub_${initData.spkId}`);
    if (!spkPrivStr || !spkPubStr) {
      const currentId = parseInt((await SecureStore.getItemAsync('spk_id')) || '1');
      if (currentId === initData.spkId) {
        spkPrivStr = await SecureStore.getItemAsync('spk_priv');
        spkPubStr  = await SecureStore.getItemAsync('spk_pub');
      } else {
        throw new Error(`X3DH: SPK ${initData.spkId} no longer available — session must be re-established`);
      }
    }
  } else {
    // Init posted before spkId tracking existed — current SPK (legacy)
    spkPrivStr = await SecureStore.getItemAsync('spk_priv');
    spkPubStr  = await SecureStore.getItemAsync('spk_pub');
  }
  if (!spkPrivStr || !spkPubStr) throw new Error('X3DH: SPK not found in SecureStore');

  const spkPriv = b64ToU8(spkPrivStr);
  const ikAPub  = b64ToU8(initData.ikPub);
  const ekAPub  = b64ToU8(initData.ekPub);

  const dh1 = x25519.getSharedSecret(spkPriv, ikAPub);  // DH(SPK_B, IK_A)
  const dh2 = x25519.getSharedSecret(ikPriv,  ekAPub);  // DH(IK_B,  EK_A)
  const dh3 = x25519.getSharedSecret(spkPriv, ekAPub);  // DH(SPK_B, EK_A)

  const parts: Uint8Array[] = [new Uint8Array(32).fill(0xff), dh1, dh2, dh3];
  if (initData.opkId !== null) {
    const opkPrivStr = await SecureStore.getItemAsync(`opk_priv_${initData.opkId}`);
    // A missing OPK private key would silently derive a DIFFERENT SK than the
    // initiator's — every message would fail with no clear cause. Fail loudly.
    if (!opkPrivStr) {
      throw new Error(`X3DH: OPK ${initData.opkId} private key missing — cannot derive session`);
    }
    parts.push(x25519.getSharedSecret(b64ToU8(opkPrivStr), ekAPub)); // DH(OPK_B, EK_A)
    await SecureStore.deleteItemAsync(`opk_priv_${initData.opkId}`); // OPK consumed
  }

  const sk = hkdf(sha256, concatU8(...parts), undefined, 'ROPE_X3DH_v1', KEY_SIZE);
  await storeConversationKey(conversationId, uint8ArrayToBase64(sk));
  // Pin the peer's identity key (reset-protocol anchor)
  await setKnownPeerIk(conversationId, initData.ikPub);

  // Initialize Double Ratchet as responder — CKs=null until first message
  // received. DHs MUST be the same SPK pair used in the X3DH above.
  await initDRAsResponder(conversationId, sk, spkPrivStr, spkPubStr);
}

// ── Double Ratchet ────────────────────────────────────────────────────────────
//
// Implements the Signal Double Ratchet algorithm:
// https://signal.org/docs/specifications/doubleratchet/
//
// Each message uses a fresh key derived from a symmetric "chain ratchet"
// (KDF_CK), and a Diffie-Hellman ratchet periodically rotates both chains to
// provide break-in recovery (post-compromise security).
//
// Key derivation:
//   KDF_RK(RK, DH_out) → HKDF-SHA256(ikm=DH_out, salt=RK, info=ROPE_DR_RK_v1)[64B]
//   KDF_CK(CK)         → HMAC-SHA256(CK, 0x01) for MK, HMAC-SHA256(CK, 0x02) for CK'
//
// State per conversation (stored in SecureStore as JSON):
//   RK, CKs, CKr — chain keys; DHs (key pair), DHr — ratchet keys
//   Ns, Nr, PN   — message counters; MK_skipped — out-of-order cache

export interface DRHeader {
  dh: string;  // sender's current ratchet public key (base64)
  n:  number;  // message number in sender's current sending chain
  pn: number;  // number of messages in sender's previous chain
}

interface DRState {
  RK:         string;                  // root key (base64, 32 bytes)
  CKs:        string | null;           // sending chain key — null for fresh responder
  CKr:        string | null;           // receiving chain key
  DHs_priv:   string;                  // own ratchet private key (base64)
  DHs_pub:    string;                  // own ratchet public key (base64)
  DHr:        string | null;           // peer's current ratchet public key (base64)
  Ns:         number;                  // messages sent in current chain
  Nr:         number;                  // messages received in current chain
  PN:         number;                  // messages in previous sending chain
  MK_skipped: Record<string, string>;  // "DHr_pub:n" → base64(mk) — out-of-order cache
}

const MAX_SKIP = 50; // max cached skipped message keys per chain

// Per-conversation mutex — drEncrypt/drDecrypt load-modify-save the ratchet
// state in SecureStore; two concurrent calls on the same conversation would
// clobber each other's writes and desynchronise the chains permanently.
const drLocks = new Map<string, Promise<void>>();

function withDRLock<T>(convId: string, fn: () => Promise<T>): Promise<T> {
  const prev = drLocks.get(convId) ?? Promise.resolve();
  const run  = prev.then(fn);
  drLocks.set(convId, run.then(() => undefined, () => undefined));
  return run;
}

// KDF_RK: new root key + new chain key from a DH output
function kdfRK(rk: Uint8Array, dhOut: Uint8Array): { newRK: Uint8Array; newCK: Uint8Array } {
  const out = hkdf(sha256, dhOut, rk, 'ROPE_DR_RK_v1', 64);
  return { newRK: out.slice(0, 32), newCK: out.slice(32) };
}

// KDF_CK: message key + next chain key from the current chain key
function kdfCK(ck: Uint8Array): { newCK: Uint8Array; mk: Uint8Array } {
  return {
    mk:    hmac(sha256, ck, new Uint8Array([0x01])),
    newCK: hmac(sha256, ck, new Uint8Array([0x02])),
  };
}

// DR state lives in an encrypted file: with up to 50 cached skipped keys the
// JSON exceeds SecureStore's 2048-byte limit and writes start failing.
async function loadDRState(convId: string): Promise<DRState | null> {
  const fromFile = await getJSON<DRState>(`dr_${convId}`);
  if (fromFile) return fromFile;

  // Migration: DR state used to live directly in SecureStore
  const legacy = await SecureStore.getItemAsync(`dr_${convId}`);
  if (!legacy) return null;
  const s = JSON.parse(legacy) as DRState;
  await setJSON(`dr_${convId}`, s);
  await SecureStore.deleteItemAsync(`dr_${convId}`);
  return s;
}

async function saveDRState(convId: string, s: DRState): Promise<void> {
  await setJSON(`dr_${convId}`, s);
}

export async function hasDRState(convId: string): Promise<boolean> {
  return (await loadDRState(convId)) !== null;
}

/** Returns true if this party has a sending chain (can send messages). */
export async function drCanSend(convId: string): Promise<boolean> {
  const s = await loadDRState(convId);
  return s !== null && s.CKs !== null;
}

// One-time message key encryption — generic AES-256-GCM from ./aes
const encryptWithMK = aesGcmEncryptString;
const decryptWithMK = aesGcmDecryptString;

// Store message keys for messages we skipped (out-of-order delivery support)
function cacheSkippedKeys(s: DRState, until: number): void {
  if (s.Nr + MAX_SKIP < until) throw new Error('DR: too many skipped messages');
  if (s.CKr !== null) {
    while (s.Nr < until) {
      const { newCK, mk } = kdfCK(b64ToU8(s.CKr));
      s.MK_skipped[`${s.DHr}:${s.Nr}`] = uint8ArrayToBase64(mk);
      s.CKr = uint8ArrayToBase64(newCK);
      s.Nr += 1;
    }
  }
}

// Perform a full DH ratchet step when we receive a new ratchet key from the peer
async function performDHRatchet(s: DRState, theirNewPub: string): Promise<void> {
  s.PN = s.Ns;
  s.Ns = 0;
  s.Nr = 0;
  s.DHr = theirNewPub;

  // New receiving chain: DH(our current key, their new key)
  const dh1 = x25519.getSharedSecret(b64ToU8(s.DHs_priv), b64ToU8(s.DHr));
  const { newRK: rk1, newCK: ck1 } = kdfRK(b64ToU8(s.RK), dh1);
  s.RK  = uint8ArrayToBase64(rk1);
  s.CKr = uint8ArrayToBase64(ck1);

  // Fresh ratchet key pair for our new sending chain
  const newPriv = await randomX25519PrivKey();
  const newPub  = x25519.getPublicKey(newPriv);
  s.DHs_priv = uint8ArrayToBase64(newPriv);
  s.DHs_pub  = uint8ArrayToBase64(newPub);

  // New sending chain: DH(our fresh key, their new key)
  const dh2 = x25519.getSharedSecret(newPriv, b64ToU8(s.DHr));
  const { newRK: rk2, newCK: ck2 } = kdfRK(b64ToU8(s.RK), dh2);
  s.RK  = uint8ArrayToBase64(rk2);
  s.CKs = uint8ArrayToBase64(ck2);
}

// Initialize DR as X3DH initiator: generates a ratchet key pair, derives CKs
// immediately using Bob's SPK, so Alice can send without waiting.
async function initDRAsInitiator(
  convId: string,
  sk: Uint8Array,
  theirSpkPub: Uint8Array
): Promise<void> {
  const dhsPriv = await randomX25519PrivKey();
  const dhsPub  = x25519.getPublicKey(dhsPriv);
  const dh      = x25519.getSharedSecret(dhsPriv, theirSpkPub);
  const { newRK, newCK } = kdfRK(sk, dh);

  await saveDRState(convId, {
    RK:         uint8ArrayToBase64(newRK),
    CKs:        uint8ArrayToBase64(newCK),
    CKr:        null,
    DHs_priv:   uint8ArrayToBase64(dhsPriv),
    DHs_pub:    uint8ArrayToBase64(dhsPub),
    DHr:        uint8ArrayToBase64(theirSpkPub),
    Ns: 0, Nr: 0, PN: 0,
    MK_skipped: {},
  });
}

// Initialize DR as X3DH responder: DHs = the SPK pair used in the X3DH
// agreement, CKs=null until first message received (Signal spec: responder
// cannot send before the initiator).
async function initDRAsResponder(
  convId: string,
  sk: Uint8Array,
  spkPrivStr: string,
  spkPubStr: string
): Promise<void> {
  await saveDRState(convId, {
    RK:         uint8ArrayToBase64(sk),
    CKs:        null,
    CKr:        null,
    DHs_priv:   spkPrivStr,
    DHs_pub:    spkPubStr,
    DHr:        null,
    Ns: 0, Nr: 0, PN: 0,
    MK_skipped: {},
  });
}

/**
 * Encrypt a plaintext message using the Double Ratchet.
 * Advances the sending chain key and returns the header needed for decryption.
 */
export function drEncrypt(
  convId: string,
  plaintext: string
): Promise<{ ciphertext: string; iv: string; header: DRHeader }> {
  return withDRLock(convId, () => drEncryptUnlocked(convId, plaintext));
}

async function drEncryptUnlocked(
  convId: string,
  plaintext: string
): Promise<{ ciphertext: string; iv: string; header: DRHeader }> {
  const s = await loadDRState(convId);
  if (!s) throw new Error('DR: no ratchet state — call x3dhInitiator/Responder first');
  if (!s.CKs) throw new Error('DR: no sending chain — wait for the first incoming message');

  const { newCK, mk } = kdfCK(b64ToU8(s.CKs));
  const header: DRHeader = { dh: s.DHs_pub, n: s.Ns, pn: s.PN };
  s.CKs = uint8ArrayToBase64(newCK);
  s.Ns  += 1;

  const { ciphertext, iv } = await encryptWithMK(mk, plaintext);
  await saveDRState(convId, s);
  return { ciphertext, iv, header };
}

/**
 * Decrypt a ciphertext using the Double Ratchet.
 * Performs a DH ratchet step automatically when a new peer key is detected.
 * Handles out-of-order delivery via the skipped-message-key cache.
 */
export function drDecrypt(
  convId: string,
  ciphertext: string,
  iv: string,
  header: DRHeader
): Promise<string> {
  return withDRLock(convId, () => drDecryptUnlocked(convId, ciphertext, iv, header));
}

async function drDecryptUnlocked(
  convId: string,
  ciphertext: string,
  iv: string,
  header: DRHeader
): Promise<string> {
  const s = await loadDRState(convId);
  if (!s) throw new Error('DR: no ratchet state for this conversation');

  // 1. Check the skipped-message-key cache (handles out-of-order delivery)
  const cacheKey = `${header.dh}:${header.n}`;
  const cachedMK = s.MK_skipped[cacheKey];
  if (cachedMK) {
    const mk = b64ToU8(cachedMK);
    delete s.MK_skipped[cacheKey];
    const plaintext = await decryptWithMK(mk, ciphertext, iv);
    await saveDRState(convId, s);
    return plaintext;
  }

  // 2. Perform a DH ratchet step if the sender switched to a new ratchet key
  if (header.dh !== s.DHr) {
    cacheSkippedKeys(s, header.pn);
    await performDHRatchet(s, header.dh);
  }

  // 3. Skip any missing messages in the current receiving chain
  cacheSkippedKeys(s, header.n);

  // 4. Derive the message key from the receiving chain
  if (!s.CKr) throw new Error('DR: receiving chain key is null after ratchet step');
  const { newCK, mk } = kdfCK(b64ToU8(s.CKr));
  s.CKr = uint8ArrayToBase64(newCK);
  s.Nr  += 1;

  const plaintext = await decryptWithMK(mk, ciphertext, iv);
  await saveDRState(convId, s);
  return plaintext;
}

// ── Conversation key storage (X3DH shared secret — kept for legacy decryption) ──

// SecureStore cannot enumerate keys, so we track every conversation that has
// crypto state in a registry — required to wipe everything on account deletion.
async function registerConversation(conversationId: string): Promise<void> {
  const raw = await SecureStore.getItemAsync('conv_registry');
  const ids: string[] = raw ? JSON.parse(raw) : [];
  if (!ids.includes(conversationId)) {
    ids.push(conversationId);
    await SecureStore.setItemAsync('conv_registry', JSON.stringify(ids));
  }
}

export async function getRegisteredConversations(): Promise<string[]> {
  const raw = await SecureStore.getItemAsync('conv_registry');
  return raw ? JSON.parse(raw) : [];
}

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
  await registerConversation(conversationId);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
}

// ── Peer identity pinning (session reset protocol) ────────────────────────────
// The contact's IK is pinned when the session is established. If the server
// later reports a different IK, the contact reinstalled (or changed device):
// the local ratchet can never re-synchronise and must be torn down.

export async function getKnownPeerIk(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`peer_ik_${conversationId}`);
}

export async function setKnownPeerIk(conversationId: string, ikPub: string): Promise<void> {
  await SecureStore.setItemAsync(`peer_ik_${conversationId}`, ikPub);
}

/**
 * Tears down ONE conversation's session state (keys + ratchet + pinned
 * identity) so a fresh X3DH can run. The decrypted history in messageStore
 * is intentionally kept — old messages stay readable.
 */
export async function wipeConversationCrypto(conversationId: string): Promise<void> {
  await SecureStore.deleteItemAsync(`conv_key_${conversationId}`);
  await SecureStore.deleteItemAsync(`dr_${conversationId}`);  // legacy location
  await deleteJSON(`dr_${conversationId}`);
  await SecureStore.deleteItemAsync(`peer_ik_${conversationId}`);
}

/**
 * Erases ALL crypto material from SecureStore: identity keys, SPK, OPKs,
 * per-conversation session keys and ratchet states.
 * Called on account deletion (GDPR) — a re-registration starts from scratch.
 */
export async function wipeAllCryptoState(): Promise<void> {
  for (const convId of await getRegisteredConversations()) {
    await SecureStore.deleteItemAsync(`conv_key_${convId}`);
    await SecureStore.deleteItemAsync(`dr_${convId}`);  // legacy location
    await deleteJSON(`dr_${convId}`);
    await SecureStore.deleteItemAsync(`peer_ik_${convId}`);
  }

  const rawNext = await SecureStore.getItemAsync('opk_next_id');
  const nextId  = rawNext ? parseInt(rawNext) : 1;
  for (let i = 1; i < nextId; i++) {
    await SecureStore.deleteItemAsync(`opk_priv_${i}`);
  }

  // Versioned SPK copies (kept across rotations)
  const spkId = parseInt((await SecureStore.getItemAsync('spk_id')) || '1');
  for (let i = 1; i <= spkId; i++) {
    await SecureStore.deleteItemAsync(`spk_priv_${i}`);
    await SecureStore.deleteItemAsync(`spk_pub_${i}`);
  }

  const flatKeys = [
    'ik_priv', 'ik_pub', 'ik_signing_priv', 'ik_signing_pub',
    'spk_priv', 'spk_pub', 'spk_sig', 'spk_id',
    'opk_next_id', 'opks_uploaded', 'conv_registry', 'state_owner_phone',
  ];
  for (const k of flatKeys) await SecureStore.deleteItemAsync(k);

  // Whatever remains in the encrypted file store (DR states) + its key
  await wipeSecureFiles();
}

// ── AES-256-GCM (legacy — decrypts pre-DR messages stored without ratchet_header) ──

export async function encryptMessage(
  plaintext: string,
  conversationId: string
): Promise<{ ciphertext: string; iv: string }> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const ivBytes = await Crypto.getRandomBytesAsync(IV_SIZE);

  const cipher = forge.cipher.createCipher('AES-GCM', b64ToBin(keyBase64));
  cipher.start({ iv: u8ToBin(ivBytes), tagLength: TAG_SIZE * 8 });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plaintext)));
  cipher.finish();

  const payload = cipher.output.getBytes() + (cipher.mode as any).tag.getBytes();

  return {
    ciphertext: binToB64(payload),
    iv:         uint8ArrayToBase64(ivBytes),
  };
}

export async function decryptMessage(
  ciphertext: string,
  iv: string,
  conversationId: string
): Promise<string> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const payload = b64ToBin(ciphertext);

  if (payload.length < TAG_SIZE) {
    throw new Error('Ciphertext too short to contain an authentication tag');
  }

  const cipherBytes = payload.slice(0, payload.length - TAG_SIZE);
  const tag         = payload.slice(payload.length - TAG_SIZE);

  const decipher = forge.cipher.createDecipher('AES-GCM', b64ToBin(keyBase64));
  decipher.start({
    iv:  b64ToBin(iv),
    tag: forge.util.createBuffer(tag),
  });
  decipher.update(forge.util.createBuffer(cipherBytes));

  if (!decipher.finish()) {
    throw new Error('Decryption failed: authentication tag mismatch (wrong key or tampered data)');
  }

  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// Base64 / binary / Uint8Array helpers live in ./aes (shared with the
// encrypted storage layers).
