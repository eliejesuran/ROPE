/**
 * ROPE Crypto — AES-256-GCM via node-forge (pure JS).
 *
 * globalThis.crypto.subtle is not reliably available in all React Native /
 * Hermes configurations. node-forge ships as a pure-JS library, requires no
 * native module, and is already a transitive dependency of the project.
 *
 * Public API is identical to the original — drop-in replacement.
 * Ciphertext layout: base64(cipher_bytes ‖ 16-byte GCM auth tag)
 * This matches Web Crypto AES-GCM output so stored messages stay readable.
 */

import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import * as forge from 'node-forge';
import { x25519, ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

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
 * first call. Replaces the Sprint 1 random-bytes stub.
 * The returned publicKey is stored in users.public_key on the server.
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
 * DH operations, derives the session key via HKDF, and stores it.
 * Returns the ephemeral key and OPK ID that Bob needs to reproduce the SK.
 */
export async function x3dhInitiator(
  conversationId: string,
  theirBundle: {
    ikPub:       string;
    ikSigningPub: string;
    spkPub:      string;
    spkSig:      string;
    opk:         { id: number; pub: string } | null;
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
    // DH(EK_A, OPK_B) — extra forward secrecy when a one-time prekey is available
    parts.push(x25519.getSharedSecret(ekPriv, b64ToU8(theirBundle.opk.pub)));
  }

  const sk = hkdf(sha256, concatU8(...parts), undefined, 'ROPE_X3DH_v1', KEY_SIZE);
  await storeConversationKey(conversationId, uint8ArrayToBase64(sk));

  return { ekPub: uint8ArrayToBase64(ekPub), opkId: theirBundle.opk?.id ?? null };
}

/**
 * X3DH responder (Bob).
 * Uses Alice's ephemeral key and the same DH operations (in reverse role)
 * to derive the identical session key.
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
}

// ── Conversation key storage ──────────────────────────────────────────────────

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
}

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

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

  // Append auth tag to ciphertext — matches Web Crypto AES-GCM layout
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

function b64ToU8(base64: string): Uint8Array {
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
