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

const KEY_SIZE = 32; // 256 bits
const IV_SIZE  = 12; // 96 bits — GCM standard
const TAG_SIZE = 16; // 128 bits — GCM authentication tag

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
    return {
      spkPub:       existing,
      spkSig:       (await SecureStore.getItemAsync('spk_sig'))!,
      spkId:        parseInt((await SecureStore.getItemAsync('spk_id')) || '1'),
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

  return {
    spkPub:       uint8ArrayToBase64(spkPub),
    spkSig:       uint8ArrayToBase64(spkSig),
    spkId:        1,
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
    opk:          { id: number; pub: string } | null;
  }
): Promise<{ ekPub: string; opkId: number | null }> {
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

  // Initialize Double Ratchet as initiator — can send immediately
  await initDRAsInitiator(conversationId, sk, spkBPub);

  return { ekPub: uint8ArrayToBase64(ekPub), opkId: theirBundle.opk?.id ?? null };
}

/**
 * X3DH responder (Bob).
 * Uses Alice's ephemeral key and the same DH operations (in reverse role)
 * to derive the identical session key, then initializes Double Ratchet as
 * responder. Bob must receive Alice's first message before he can send.
 */
export async function x3dhResponder(
  conversationId: string,
  initData: { ikPub: string; ekPub: string; opkId: number | null }
): Promise<void> {
  const ikPriv  = b64ToU8((await SecureStore.getItemAsync('ik_priv'))!);
  const spkPriv = b64ToU8((await SecureStore.getItemAsync('spk_priv'))!);
  const ikAPub  = b64ToU8(initData.ikPub);
  const ekAPub  = b64ToU8(initData.ekPub);

  const dh1 = x25519.getSharedSecret(spkPriv, ikAPub);  // DH(SPK_B, IK_A)
  const dh2 = x25519.getSharedSecret(ikPriv,  ekAPub);  // DH(IK_B,  EK_A)
  const dh3 = x25519.getSharedSecret(spkPriv, ekAPub);  // DH(SPK_B, EK_A)

  const parts: Uint8Array[] = [new Uint8Array(32).fill(0xff), dh1, dh2, dh3];
  if (initData.opkId !== null) {
    const opkPrivStr = await SecureStore.getItemAsync(`opk_priv_${initData.opkId}`);
    if (opkPrivStr) {
      parts.push(x25519.getSharedSecret(b64ToU8(opkPrivStr), ekAPub)); // DH(OPK_B, EK_A)
      await SecureStore.deleteItemAsync(`opk_priv_${initData.opkId}`); // OPK consumed
    }
  }

  const sk = hkdf(sha256, concatU8(...parts), undefined, 'ROPE_X3DH_v1', KEY_SIZE);
  await storeConversationKey(conversationId, uint8ArrayToBase64(sk));

  // Initialize Double Ratchet as responder — CKs=null until first message received
  await initDRAsResponder(conversationId, sk);
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

async function loadDRState(convId: string): Promise<DRState | null> {
  const raw = await SecureStore.getItemAsync(`dr_${convId}`);
  return raw ? (JSON.parse(raw) as DRState) : null;
}

async function saveDRState(convId: string, s: DRState): Promise<void> {
  await SecureStore.setItemAsync(`dr_${convId}`, JSON.stringify(s));
}

export async function hasDRState(convId: string): Promise<boolean> {
  return (await SecureStore.getItemAsync(`dr_${convId}`)) !== null;
}

/** Returns true if this party has a sending chain (can send messages). */
export async function drCanSend(convId: string): Promise<boolean> {
  const s = await loadDRState(convId);
  return s !== null && s.CKs !== null;
}

// AES-256-GCM encrypt with a one-time message key (node-forge)
async function encryptWithMK(
  mk: Uint8Array,
  plaintext: string
): Promise<{ ciphertext: string; iv: string }> {
  const ivBytes = await Crypto.getRandomBytesAsync(IV_SIZE);
  const cipher  = forge.cipher.createCipher('AES-GCM', u8ToBin(mk));
  cipher.start({ iv: u8ToBin(ivBytes), tagLength: TAG_SIZE * 8 });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plaintext)));
  cipher.finish();
  const payload = cipher.output.getBytes() + (cipher.mode as any).tag.getBytes();
  return { ciphertext: binToB64(payload), iv: uint8ArrayToBase64(ivBytes) };
}

// AES-256-GCM decrypt with a one-time message key (node-forge)
async function decryptWithMK(
  mk: Uint8Array,
  ciphertext: string,
  iv: string
): Promise<string> {
  const payload     = b64ToBin(ciphertext);
  const cipherBytes = payload.slice(0, payload.length - TAG_SIZE);
  const tag         = payload.slice(payload.length - TAG_SIZE);
  const decipher    = forge.cipher.createDecipher('AES-GCM', u8ToBin(mk));
  decipher.start({ iv: b64ToBin(iv), tag: forge.util.createBuffer(tag) });
  decipher.update(forge.util.createBuffer(cipherBytes));
  if (!decipher.finish()) throw new Error('DR decrypt: authentication tag mismatch');
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

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

// Initialize DR as X3DH responder: DHs = SPK key pair, CKs=null until first
// message received (Signal spec: responder cannot send before initiator).
async function initDRAsResponder(convId: string, sk: Uint8Array): Promise<void> {
  const spkPrivStr = await SecureStore.getItemAsync('spk_priv');
  const spkPubStr  = await SecureStore.getItemAsync('spk_pub');
  if (!spkPrivStr || !spkPubStr) throw new Error('DR: SPK not found in SecureStore');

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
 * Migrate a Sprint-2 session (X3DH only) to Double Ratchet.
 * Called when conv_key exists but dr_state does not.
 *
 * @param role       'initiator' if this device posted the X3DH init, else 'responder'
 * @param theirSpkPub Required when role='initiator'; the contact's SPK public key (base64)
 */
export async function initDRFromExistingSession(
  convId: string,
  role: 'initiator' | 'responder',
  theirSpkPub?: string
): Promise<void> {
  const skB64 = await SecureStore.getItemAsync(`conv_key_${convId}`);
  if (!skB64) throw new Error('DR migration: no session key found for conversation');
  const sk = b64ToU8(skB64);
  if (role === 'initiator') {
    if (!theirSpkPub) throw new Error('DR migration: theirSpkPub required for initiator role');
    await initDRAsInitiator(convId, sk, b64ToU8(theirSpkPub));
  } else {
    await initDRAsResponder(convId, sk);
  }
}

/**
 * Encrypt a plaintext message using the Double Ratchet.
 * Advances the sending chain key and returns the header needed for decryption.
 */
export async function drEncrypt(
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
export async function drDecrypt(
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

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
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

// ── Base64 / binary / Uint8Array helpers ─────────────────────────────────────

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function u8ToBin(bytes: Uint8Array): string {
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return bin;
}

function b64ToBin(base64: string): string {
  return atob(base64);
}

function binToB64(bin: string): string {
  return btoa(bin);
}

export function b64ToU8(base64: string): Uint8Array {
  const bin   = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function concatU8(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const arr of arrays) { out.set(arr, offset); offset += arr.length; }
  return out;
}
