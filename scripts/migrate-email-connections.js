/**
 * Creates the "EmailConnection" table used by the Gmail integration.
 * Safe to run more than once (every statement is idempotent).
 *
 * Usage (from the backend folder, with DATABASE_URL set in .env):
 *   node scripts/migrate-email-connections.js
 */
require("dotenv").config();
const { Pool } = require("pg");

const statements = [
  `CREATE TABLE IF NOT EXISTS "public"."EmailConnection" (
    "id" text NOT NULL,
    "userId" text NOT NULL,
    "provider" text NOT NULL,
    "accountEmail" text NOT NULL,
    "refreshTokenEnc" text NOT NULL,
    "scopes" text,
    "lastPushedAt" timestamptz,
    "lastSignatureId" text,
    "createdAt" timestamptz DEFAULT (now()) NOT NULL,
    "updatedAt" timestamptz DEFAULT (now()) NOT NULL,
    PRIMARY KEY ("id")
  )`,
  `DO $$ BEGIN
    ALTER TABLE "public"."EmailConnection"
      ADD CONSTRAINT "EmailConnection_userId_provider_accountEmail_key"
      UNIQUE ("userId", "provider", "accountEmail");
  EXCEPTION WHEN duplicate_table OR duplicate_object THEN NULL;
  END $$`,
  `CREATE INDEX IF NOT EXISTS "EmailConnection_userId_idx" ON "public"."EmailConnection" ("userId")`,
  `DO $$ BEGIN
    ALTER TABLE "public"."EmailConnection"
      ADD CONSTRAINT "EmailConnection_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "public"."User" ("id") ON DELETE CASCADE;
  EXCEPTION WHEN duplicate_object THEN NULL;
  END $$`,
  // Zoho support: provider specific, non secret details (data center and signature id) as JSON text
  `ALTER TABLE "public"."EmailConnection" ADD COLUMN IF NOT EXISTS "metadata" TEXT`,
];

async function migrate() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    for (const statement of statements) {
      await pool.query(statement);
    }
    console.log('✅ Migration successful: "EmailConnection" table is ready.');
  } catch (err) {
    console.error("❌ Migration failed:", err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

migrate();
