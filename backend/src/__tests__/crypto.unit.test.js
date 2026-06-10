/**
 * AES-256-GCM unit tests — pure, no DB, no network.
 * Uses Node.js WebCrypto (same API as mobile's globalThis.crypto.subtle).
 * Validates the encryption primitives used by ROPE end-to-end.
 */
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;

function b64(buf) { return Buffer.from(buf).toString('base64'); }
function unb64(s) { return Buffer.from(s, 'base64'); }

async function generateKeyBase64() {
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const raw = await subtle.exportKey('raw', key);
  return b64(raw);
}

async function importKey(keyB64, usage) {
  return subtle.importKey('raw', unb64(keyB64), { name: 'AES-GCM' }, false, [usage]);
}

async function encrypt(plaintext, keyB64) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await importKey(keyB64, 'encrypt');
  const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv }, key, Buffer.from(plaintext));
  return { ciphertext: b64(encrypted), iv: b64(iv) };
}

async function decrypt(ciphertext, ivB64, keyB64) {
  const key = await importKey(keyB64, 'decrypt');
  const decrypted = await subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(ivB64) },
    key,
    unb64(ciphertext)
  );
  return Buffer.from(decrypted).toString();
}

describe('AES-256-GCM (ROPE mobile crypto primitives)', () => {
  let keyB64;

  beforeAll(async () => {
    keyB64 = await generateKeyBase64();
  });

  it('encrypts then decrypts back to original plaintext', async () => {
    const { ciphertext, iv } = await encrypt('Bonjour ROPE!', keyB64);
    expect(await decrypt(ciphertext, iv, keyB64)).toBe('Bonjour ROPE!');
  });

  it('handles empty string', async () => {
    const { ciphertext, iv } = await encrypt('', keyB64);
    expect(await decrypt(ciphertext, iv, keyB64)).toBe('');
  });

  it('handles unicode and emojis', async () => {
    const msg = 'Ça marche 🔒 très bien';
    const { ciphertext, iv } = await encrypt(msg, keyB64);
    expect(await decrypt(ciphertext, iv, keyB64)).toBe(msg);
  });

  it('produces different ciphertext for the same plaintext (random IV)', async () => {
    const { ciphertext: c1 } = await encrypt('same message', keyB64);
    const { ciphertext: c2 } = await encrypt('same message', keyB64);
    expect(c1).not.toBe(c2);
  });

  it('ciphertext does not contain the plaintext', async () => {
    const { ciphertext } = await encrypt('super secret', keyB64);
    expect(unb64(ciphertext).toString('utf8')).not.toContain('super secret');
  });

  it('decryption fails with a different key (wrong key)', async () => {
    const { ciphertext, iv } = await encrypt('test', keyB64);
    const otherKey = await generateKeyBase64();
    await expect(decrypt(ciphertext, iv, otherKey)).rejects.toThrow();
  });

  it('decryption fails when ciphertext is tampered (GCM auth tag)', async () => {
    const { ciphertext, iv } = await encrypt('test', keyB64);
    const tampered = Buffer.from(unb64(ciphertext));
    tampered[0] ^= 0xff;
    await expect(decrypt(tampered.toString('base64'), iv, keyB64)).rejects.toThrow();
  });

  it('IV is exactly 12 bytes (96-bit GCM standard)', async () => {
    const { iv } = await encrypt('test', keyB64);
    expect(unb64(iv).length).toBe(12);
  });

  it('key is exactly 32 bytes (AES-256)', () => {
    expect(unb64(keyB64).length).toBe(32);
  });
});
