/**
 * ROPE Crypto Service
 * ──────────────────────
 * AES-256-GCM end-to-end encryption.
 * All encryption/decryption happens on the device.
 * The server NEVER receives plaintext or keys.
 *
 * Key exchange for Sprint 1:
 * - Each user generates a keypair on first launch
 * - The PUBLIC key is sent to the server (stored per user)
 * - The PRIVATE key NEVER leaves the device (stored in SecureStore)
 * - A shared conversation key is derived from both keys (ECDH)
 *
 * Sprint 2: Replace with Signal Protocol (X3DH + Double Ratchet)
 * for perfect forward secrecy.
 */

import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

const KEY_SIZE = 32; // 256 bits
const IV_SIZE = 12;  // 96 bits for GCM

// ── Key generation ────────────────────────────────────────────────────────────

/**
 * Generate a random AES-256 key for a conversation.
 * In Sprint 1, this key must be shared out-of-band (shown as QR or code).
 * In Sprint 2, ECDH will automate this.
 */
export async function generateConversationKey(): Promise<string> {
  const keyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);
  return uint8ArrayToBase64(keyBytes);
}

/**
 * Generate a random device keypair (stored locally).
 * publicKey → sent to server
 * privateKey → stays in SecureStore forever
 */
export async function getOrCreateDeviceKeypair(): Promise<{ publicKey: string }> {
  const existing = await SecureStore.getItemAsync('device_private_key');
  if (existing) {
    const pubKey = await SecureStore.getItemAsync('device_public_key');
    return { publicKey: pubKey! };
  }

  // Sprint 1: we use a random 32-byte key as "public key" identifier
  // Sprint 2: replace with real ECDH (P-256 or X25519) keypair
  const privateKeyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);
  const publicKeyBytes = await Crypto.getRandomBytesAsync(KEY_SIZE);

  const privateKey = uint8ArrayToBase64(privateKeyBytes);
  const publicKey = uint8ArrayToBase64(publicKeyBytes);

  await SecureStore.setItemAsync('device_private_key', privateKey);
  await SecureStore.setItemAsync('device_public_key', publicKey);

  return { publicKey };
}

// ── Conversation key management ───────────────────────────────────────────────

export async function storeConversationKey(conversationId: string, key: string): Promise<void> {
  await SecureStore.setItemAsync(`conv_key_${conversationId}`, key);
}

export async function getConversationKey(conversationId: string): Promise<string | null> {
  return SecureStore.getItemAsync(`conv_key_${conversationId}`);
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

export async function encryptMessage(
  plaintext: string,
  conversationId: string
): Promise<{ ciphertext: string; iv: string }> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const key = base64ToUint8Array(keyBase64);
  const iv = await Crypto.getRandomBytesAsync(IV_SIZE);
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // AES-256-GCM via WebCrypto (available in React Native via Expo)
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    plaintextBytes
  );

  return {
    ciphertext: uint8ArrayToBase64(new Uint8Array(encrypted)),
    iv: uint8ArrayToBase64(iv),
  };
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

export async function decryptMessage(
  ciphertext: string,
  iv: string,
  conversationId: string
): Promise<string> {
  const keyBase64 = await getConversationKey(conversationId);
  if (!keyBase64) throw new Error('No key found for this conversation');

  const key = base64ToUint8Array(keyBase64);
  const ciphertextBytes = base64ToUint8Array(ciphertext);
  const ivBytes = base64ToUint8Array(iv);

  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    cryptoKey,
    ciphertextBytes
  );

  return new TextDecoder().decode(decrypted);
}

// ── Utils ─────────────────────────────────────────────────────────────────────

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
