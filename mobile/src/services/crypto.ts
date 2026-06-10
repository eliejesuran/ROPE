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

const KEY_SIZE = 32; // 256 bits
const IV_SIZE  = 12; // 96 bits — GCM standard
const TAG_SIZE = 16; // 128 bits — GCM authentication tag

// ── Key generation ──────────────────────────────────────────────────────────

export async function generateConversationKey(): Promise<string> {
  const keyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);
  return uint8ArrayToBase64(keyBytes);
}

export async function getOrCreateDeviceKeypair(): Promise<{ publicKey: string }> {
  const existing = await SecureStore.getItemAsync('device_private_key');
  if (existing) {
    return { publicKey: (await SecureStore.getItemAsync('device_public_key'))! };
  }
  // Placeholder keypair — replaced by Curve25519 in Sprint 2 (X3DH)
  const priv = await Crypto.getRandomBytesAsync(KEY_SIZE);
  const pub  = await Crypto.getRandomBytesAsync(KEY_SIZE);
  await SecureStore.setItemAsync('device_private_key', uint8ArrayToBase64(priv));
  await SecureStore.setItemAsync('device_public_key',  uint8ArrayToBase64(pub));
  return { publicKey: uint8ArrayToBase64(pub) };
}

// ── Conversation key storage ────────────────────────────────────────────────

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
}

// ── AES-256-GCM ─────────────────────────────────────────────────────────────

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

// ── Base64 / binary helpers ─────────────────────────────────────────────────

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
