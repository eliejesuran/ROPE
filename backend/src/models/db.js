const { Pool } = require('pg');
const logger = require('../services/logger');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

const SCHEMA = `
  -- Users identified by phone number only (GDPR minimisation)
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash TEXT UNIQUE NOT NULL,   -- bcrypt hash of E164 phone number
    phone_last4 TEXT NOT NULL,         -- last 4 digits, for display only
    display_name TEXT,                 -- optional, user-defined
    public_key TEXT NOT NULL,          -- AES key exchange public material
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ            -- soft delete for GDPR right to erasure
  );

  -- OTP codes (short-lived)
  CREATE TABLE IF NOT EXISTS otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash TEXT NOT NULL,
    code_hash TEXT NOT NULL,           -- hashed OTP, never stored in clear
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  -- Conversations between two users
  CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_a UUID REFERENCES users(id) ON DELETE CASCADE,
    participant_b UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(participant_a, participant_b)
  );

  -- Messages: server stores only ciphertext, never plaintext
  CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ciphertext TEXT NOT NULL,          -- AES-256-GCM encrypted payload (base64)
    iv TEXT NOT NULL,                  -- Initialisation vector (base64)
    sent_at TIMESTAMPTZ DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ            -- GDPR: soft delete, purged after 30 days
  );

  -- Indexes
  CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, sent_at DESC);
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
  CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone_hash, expires_at);
`;

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(SCHEMA);
    logger.info('Database schema verified/created');
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB };
