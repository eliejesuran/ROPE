/**
 * Generic AES-256-GCM primitives + base64 helpers (node-forge, pure JS).
 *
 * Shared by crypto.ts (Double Ratchet message keys), messageStore.ts and
 * secureFiles.ts (local encrypted persistence). Lives in its own module so
 * the storage layers don't have to import crypto.ts (circular import).
 *
 * Ciphertext layout: base64(cipher_bytes ‖ 16-byte GCM auth tag)
 */

import * as Crypto from 'expo-crypto';
import * as forge from 'node-forge';

export const IV_SIZE  = 12; // 96 bits — GCM standard
export const TAG_SIZE = 16; // 128 bits — GCM authentication tag

export async function aesGcmEncryptString(
  key: Uint8Array,
  plaintext: string
): Promise<{ ciphertext: string; iv: string }> {
  const ivBytes = await Crypto.getRandomBytesAsync(IV_SIZE);
  const cipher  = forge.cipher.createCipher('AES-GCM', u8ToBin(key));
  cipher.start({ iv: u8ToBin(ivBytes), tagLength: TAG_SIZE * 8 });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plaintext)));
  cipher.finish();
  const payload = cipher.output.getBytes() + (cipher.mode as any).tag.getBytes();
  return { ciphertext: binToB64(payload), iv: uint8ArrayToBase64(ivBytes) };
}

export async function aesGcmDecryptString(
  key: Uint8Array,
  ciphertext: string,
  iv: string
): Promise<string> {
  const payload     = b64ToBin(ciphertext);
  const cipherBytes = payload.slice(0, payload.length - TAG_SIZE);
  const tag         = payload.slice(payload.length - TAG_SIZE);
  const decipher    = forge.cipher.createDecipher('AES-GCM', u8ToBin(key));
  decipher.start({ iv: b64ToBin(iv), tag: forge.util.createBuffer(tag) });
  decipher.update(forge.util.createBuffer(cipherBytes));
  if (!decipher.finish()) throw new Error('AES-GCM decrypt: authentication tag mismatch');
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// ── Base64 / binary / Uint8Array helpers ─────────────────────────────────────

export function uint8ArrayToBase64(bytes: Uint8Array): string {
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

export function u8ToBin(bytes: Uint8Array): string {
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return bin;
}

export function b64ToBin(base64: string): string {
  return atob(base64);
}

export function binToB64(bin: string): string {
  return btoa(bin);
}

export function b64ToU8(base64: string): Uint8Array {
  const bin   = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function concatU8(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const arr of arrays) { out.set(arr, offset); offset += arr.length; }
  return out;
}
