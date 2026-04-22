/**
 * ROPE Crypto Service
 * ──────────────────────
 * AES-256-CTR end-to-end encryption via aes-js (pure JS, works in React Native).
 * All encryption/decryption happens on the device.
 * The server NEVER receives plaintext or keys.
 */

import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import AES from 'aes-js';

const KEY_SIZE = 32; // 256 bits
const IV_SIZE  = 16; // 128 bits for CTR

// ── Key generation ────────────────────────────────────────────────────────────

export async function generateConversationKey(): Promise<string> {
  const keyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);
  return uint8ArrayToBase64(keyBytes);
}

export async function getOrCreateDeviceKeypair(): Promise<{ publicKey: string }> {
  const existing = await SecureStore.getItemAsync('device_private_key');
  if (existing) {
    const pubKey = await SecureStore.getItemAsync('device_public_key');
    return { publicKey: pubKey! };
  }

  const privateKeyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);
  const publicKeyBytes  = await Crypto.getRandomBytesAsync(KEY_SIZE);

  await SecureStore.setItemAsync('device_private_key', uint8ArrayToBase64(privateKeyBytes));
  await SecureStore.setItemAsync('device_public_key',  uint8ArrayToBase64(publicKeyBytes));

  return { publicKey: uint8ArrayToBase64(publicKeyBytes) };
}

// ── Conversation key storage ──────────────────────────────────────────────────

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
}

// ── Encrypt (AES-256-CTR) ─────────────────────────────────────────────────────

export async function encryptMessage(
  plaintext: string,
  conversationId: string
): Promise<{ ciphertext: string; iv: string }> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const key            = base64ToUint8Array(keyBase64);
  const ivBytes        = await Crypto.getRandomBytesAsync(IV_SIZE);
  const plaintextBytes = new TextEncoder().encode(plaintext);

  const aesCtr   = new AES.ModeOfOperation.ctr(key, new AES.Counter(ivBytes));
  const encrypted = aesCtr.encrypt(plaintextBytes);

  return {
    ciphertext: uint8ArrayToBase64(encrypted),
    iv:         uint8ArrayToBase64(ivBytes),
  };
}

// ── Decrypt (AES-256-CTR) ─────────────────────────────────────────────────────

export async function decryptMessage(
  ciphertext: string,
  iv: string,
  conversationId: string
): Promise<string> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const key             = base64ToUint8Array(keyBase64);
  const ivBytes         = base64ToUint8Array(iv);
  const ciphertextBytes = base64ToUint8Array(ciphertext);

  const aesCtr   = new AES.ModeOfOperation.ctr(key, new AES.Counter(ivBytes));
  const decrypted = aesCtr.decrypt(ciphertextBytes);

  return new TextDecoder().decode(decrypted);
}

// ── Utils ─────────────────────────────────────────────────────────────────────

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
