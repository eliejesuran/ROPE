/**
 * Encrypted JSON file store.
 *
 * SecureStore values are capped at 2048 bytes — too small for the Double
 * Ratchet state (up to 50 cached skipped keys ≈ 4 KB). Values here live as
 * files in the app sandbox, AES-256-GCM encrypted under a device-local key
 * that stays in SecureStore (so the at-rest security model is unchanged:
 * stealing the files without the keychain yields nothing).
 */

import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';
import { aesGcmEncryptString, aesGcmDecryptString, uint8ArrayToBase64, b64ToU8 } from './aes';

const DIR = `${FileSystem.documentDirectory}securefiles/`;

// Per-name write serialization — load-modify-save callers (DR state) must
// never interleave two writes to the same file.
const writeLocks = new Map<string, Promise<void>>();

function withWriteLock(name: string, fn: () => Promise<void>): Promise<void> {
  const prev = writeLocks.get(name) ?? Promise.resolve();
  const run  = prev.then(fn);
  writeLocks.set(name, run.then(() => undefined, () => undefined));
  return run;
}

async function getFileKey(): Promise<Uint8Array> {
  let keyB64 = await SecureStore.getItemAsync('securefiles_key');
  if (!keyB64) {
    const bytes = await Crypto.getRandomBytesAsync(32);
    keyB64 = uint8ArrayToBase64(bytes);
    await SecureStore.setItemAsync('securefiles_key', keyB64);
  }
  return b64ToU8(keyB64);
}

function pathFor(name: string): string {
  return `${DIR}${name}.json`;
}

/** Reads and decrypts a stored JSON value. Returns null if absent/corrupt. */
export async function getJSON<T>(name: string): Promise<T | null> {
  try {
    const info = await FileSystem.getInfoAsync(pathFor(name));
    if (!info.exists) return null;
    const raw = await FileSystem.readAsStringAsync(pathFor(name));
    const { iv, data } = JSON.parse(raw);
    const key = await getFileKey();
    return JSON.parse(await aesGcmDecryptString(key, data, iv)) as T;
  } catch {
    return null;
  }
}

/** Encrypts and persists a JSON value. */
export async function setJSON(name: string, value: unknown): Promise<void> {
  return withWriteLock(name, async () => {
    const key = await getFileKey();
    const { ciphertext, iv } = await aesGcmEncryptString(key, JSON.stringify(value));
    await FileSystem.makeDirectoryAsync(DIR, { intermediates: true }).catch(() => {});
    await FileSystem.writeAsStringAsync(pathFor(name), JSON.stringify({ iv, data: ciphertext }));
  });
}

export async function deleteJSON(name: string): Promise<void> {
  await FileSystem.deleteAsync(pathFor(name), { idempotent: true }).catch(() => {});
}

/** Erases every stored file + the encryption key (account deletion). */
export async function wipeSecureFiles(): Promise<void> {
  await FileSystem.deleteAsync(DIR, { idempotent: true }).catch(() => {});
  await SecureStore.deleteItemAsync('securefiles_key');
}
