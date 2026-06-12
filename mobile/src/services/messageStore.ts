/**
 * Local plaintext store — Signal model.
 *
 * Double Ratchet message keys are single-use (forward secrecy): a message can
 * only ever be decrypted ONCE. So the plaintext is persisted locally right
 * after the first decryption (or at send time for own messages) and served
 * from here on every subsequent display. The server history is only used to
 * list message metadata and fetch never-seen ciphertexts.
 *
 * Storage: one JSON file per conversation in the app's document directory,
 * encrypted with AES-256-GCM under a device-local key held in SecureStore.
 * Entries carry the message's expiry so ephemeral messages also vanish from
 * the local store, even offline.
 */

import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';
import { aesGcmEncryptString, aesGcmDecryptString, b64ToU8 } from './aes';

const STORE_DIR = `${FileSystem.documentDirectory}msgstore/`;

interface StoredMessage {
  p: string;             // plaintext
  exp?: string | null;   // expires_at ISO — pruned locally once past
}

type ConvStore = Record<string, StoredMessage>; // messageId → entry

// In-memory cache + per-conversation write serialization
const memCache     = new Map<string, ConvStore>();
const fileLocks    = new Map<string, Promise<void>>();
const loadPromises = new Map<string, Promise<ConvStore>>();

function withFileLock(convId: string, fn: () => Promise<void>): Promise<void> {
  const prev = fileLocks.get(convId) ?? Promise.resolve();
  const run  = prev.then(fn);
  fileLocks.set(convId, run.then(() => undefined, () => undefined));
  return run;
}

async function getStoreKey(): Promise<Uint8Array> {
  let keyB64 = await SecureStore.getItemAsync('msgstore_key');
  if (!keyB64) {
    const bytes = await Crypto.getRandomBytesAsync(32);
    keyB64 = btoa(String.fromCharCode(...bytes));
    await SecureStore.setItemAsync('msgstore_key', keyB64);
  }
  return b64ToU8(keyB64);
}

function fileFor(convId: string): string {
  return `${STORE_DIR}${convId}.json`;
}

function loadConvStore(convId: string): Promise<ConvStore> {
  const cached = memCache.get(convId);
  if (cached) return Promise.resolve(cached);

  // Memoise the in-flight load so concurrent callers share ONE store object —
  // two parallel loads would each build their own copy and lose writes.
  let pending = loadPromises.get(convId);
  if (!pending) {
    pending = doLoadConvStore(convId).finally(() => loadPromises.delete(convId));
    loadPromises.set(convId, pending);
  }
  return pending;
}

async function doLoadConvStore(convId: string): Promise<ConvStore> {
  let store: ConvStore = {};
  try {
    const info = await FileSystem.getInfoAsync(fileFor(convId));
    if (info.exists) {
      const raw = await FileSystem.readAsStringAsync(fileFor(convId));
      const { iv, data } = JSON.parse(raw);
      const key = await getStoreKey();
      store = JSON.parse(await aesGcmDecryptString(key, data, iv));
    }
  } catch {
    // Unreadable/corrupt store — start fresh rather than blocking the chat
    store = {};
  }

  // Honour ephemeral expiry locally, even if the server purge hasn't run
  const now = Date.now();
  let pruned = false;
  for (const [id, entry] of Object.entries(store)) {
    if (entry.exp && new Date(entry.exp).getTime() <= now) {
      delete store[id];
      pruned = true;
    }
  }

  memCache.set(convId, store);
  if (pruned) await persistConvStore(convId);
  return store;
}

async function persistConvStore(convId: string): Promise<void> {
  return withFileLock(convId, async () => {
    const store = memCache.get(convId) ?? {};
    const key   = await getStoreKey();
    const { ciphertext, iv } = await aesGcmEncryptString(key, JSON.stringify(store));
    await FileSystem.makeDirectoryAsync(STORE_DIR, { intermediates: true }).catch(() => {});
    await FileSystem.writeAsStringAsync(fileFor(convId), JSON.stringify({ iv, data: ciphertext }));
  });
}

/** Returns the cached plaintext for a message, or null if never decrypted here. */
export async function getPlaintext(convId: string, msgId: string): Promise<string | null> {
  const store = await loadConvStore(convId);
  const entry = store[msgId];
  if (!entry) return null;
  if (entry.exp && new Date(entry.exp).getTime() <= Date.now()) {
    delete store[msgId];
    await persistConvStore(convId);
    return null;
  }
  return entry.p;
}

/** Persists a decrypted (or just-sent) plaintext. Write-through to disk. */
export async function setPlaintext(
  convId: string,
  msgId: string,
  plaintext: string,
  expiresAt?: string | null
): Promise<void> {
  const store = await loadConvStore(convId);
  store[msgId] = { p: plaintext, ...(expiresAt ? { exp: expiresAt } : {}) };
  await persistConvStore(convId);
}

/** Deletes one conversation's local history (e.g. conversation removal). */
export async function deleteConversationStore(convId: string): Promise<void> {
  memCache.delete(convId);
  await FileSystem.deleteAsync(fileFor(convId), { idempotent: true }).catch(() => {});
}

/** Erases the whole local message store + its encryption key (GDPR deletion). */
export async function wipeMessageStore(): Promise<void> {
  memCache.clear();
  await FileSystem.deleteAsync(STORE_DIR, { idempotent: true }).catch(() => {});
  await SecureStore.deleteItemAsync('msgstore_key');
}
