/**
 * ROPE Crypto — AES-256-GCM via Web Crypto API (Hermes / RN 0.73+)
 * All encryption happens on-device. Server never sees plaintext or keys.
 */

import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

const KEY_SIZE = 32; // 256 bits
const IV_SIZE  = 12; // 96 bits — GCM standard

// ── Key generation ─────────────────────────────────────────────────────────

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

// ── Conversation key storage ───────────────────────────────────────────────

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
}

// ── AES-256-GCM ────────────────────────────────────────────────────────────

async function importAesKey(base64: string, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw', base64ToUint8Array(base64), { name: 'AES-GCM' }, false, [usage]
  );
}

export async function encryptMessage(
  plaintext: string,
  conversationId: string
): Promise<{ ciphertext: string; iv: string }> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const iv  = await Crypto.getRandomBytesAsync(IV_SIZE);
  const key = await importAesKey(keyBase64, 'encrypt');

  const encrypted = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );

  return {
    ciphertext: uint8ArrayToBase64(new Uint8Array(encrypted)),
    iv: uint8ArrayToBase64(iv),
  };
}

export async function decryptMessage(
  ciphertext: string,
  iv: string,
  conversationId: string
): Promise<string> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const key = await importAesKey(keyBase64, 'decrypt');

  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToUint8Array(iv) },
    key,
    base64ToUint8Array(ciphertext)
  );

  return new TextDecoder().decode(decrypted);
}

// ── Utils ──────────────────────────────────────────────────────────────────

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
