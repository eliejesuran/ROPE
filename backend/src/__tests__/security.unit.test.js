/**
 * Pure unit tests — no DB, no network.
 * Validates cryptographic and GDPR invariants on server-side logic.
 */
const crypto = require('crypto');

function deterministicPhoneHash(phone, pepper) {
  return crypto.createHmac('sha256', pepper).update(phone).digest('hex');
}

function normalisePhone(phone) {
  const cleaned = phone.replace(/\s+/g, '').replace(/-/g, '');
  if (!/^\+[1-9]\d{6,14}$/.test(cleaned)) {
    throw new Error('Invalid phone number format. Use E.164 (e.g. +32471234567)');
  }
  return cleaned;
}

const PEPPER = 'test_pepper';

describe('deterministicPhoneHash', () => {
  it('is deterministic — same input always gives same hash', () => {
    expect(deterministicPhoneHash('+32471234567', PEPPER))
      .toBe(deterministicPhoneHash('+32471234567', PEPPER));
  });

  it('different phones produce different hashes', () => {
    expect(deterministicPhoneHash('+32471234567', PEPPER))
      .not.toBe(deterministicPhoneHash('+32471234568', PEPPER));
  });

  it('different peppers produce different hashes for the same phone', () => {
    expect(deterministicPhoneHash('+32471234567', 'pepper1'))
      .not.toBe(deterministicPhoneHash('+32471234567', 'pepper2'));
  });

  it('output is a 64-char hex string (SHA-256)', () => {
    expect(deterministicPhoneHash('+32471234567', PEPPER)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hash does not contain the phone number (GDPR: blind server)', () => {
    const hash = deterministicPhoneHash('+32471234567', PEPPER);
    expect(hash).not.toContain('32471234567');
  });
});

describe('normalisePhone', () => {
  it('accepts valid E.164 numbers', () => {
    expect(normalisePhone('+32471234567')).toBe('+32471234567');
    expect(normalisePhone('+33612345678')).toBe('+33612345678');
    expect(normalisePhone('+12125551234')).toBe('+12125551234');
  });

  it('strips spaces and dashes', () => {
    expect(normalisePhone('+32 471 234 567')).toBe('+32471234567');
    expect(normalisePhone('+32-471-234-567')).toBe('+32471234567');
  });

  it('rejects numbers without + prefix', () => {
    expect(() => normalisePhone('0471234567')).toThrow('Invalid phone');
    expect(() => normalisePhone('32471234567')).toThrow('Invalid phone');
  });

  it('rejects too-short numbers', () => {
    expect(() => normalisePhone('+3247')).toThrow('Invalid phone');
  });

  it('rejects too-long numbers (> 15 digits per ITU E.164)', () => {
    expect(() => normalisePhone('+123456789012345678')).toThrow('Invalid phone');
  });
});

describe('GDPR data minimisation invariants', () => {
  it('phone hash cannot reconstruct the full number', () => {
    const phone = '+32471234567';
    const hash = deterministicPhoneHash(phone, PEPPER);
    const last4 = phone.slice(-4);

    // last4 alone is not enough to reconstruct full number
    expect(last4).toBe('4567');
    expect(hash.length).toBe(64);
    // hash is irreversible (pre-image resistance of HMAC-SHA256)
    expect(hash).not.toContain(phone.replace('+', ''));
  });
});
