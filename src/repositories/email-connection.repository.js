require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const PUBLIC_COLUMNS = `"id", "userId", "provider", "accountEmail", "scopes", "lastPushedAt", "lastSignatureId", "createdAt", "updatedAt"`;
const ALL_COLUMNS = `${PUBLIC_COLUMNS}, "refreshTokenEnc"`;

/**
 * Connected mailbox accounts (Gmail first). The refresh token is stored encrypted.
 * `refreshTokenEnc` is only returned by findWithTokenByUser, never by public lookups.
 */
const emailConnectionRepository = {
  async findByUser(userId, provider) {
    const res = await pool.query(
      `SELECT ${PUBLIC_COLUMNS}
       FROM "EmailConnection"
       WHERE "userId" = $1 AND "provider" = $2
       ORDER BY "updatedAt" DESC`,
      [userId, provider]
    );
    return res.rows;
  },

  async findWithTokenByUser(userId, provider) {
    const res = await pool.query(
      `SELECT ${ALL_COLUMNS}
       FROM "EmailConnection"
       WHERE "userId" = $1 AND "provider" = $2
       ORDER BY "updatedAt" DESC
       LIMIT 1`,
      [userId, provider]
    );
    return res.rows[0] || null;
  },

  /**
   * One connection per user and provider: saving a connection for a different
   * account email removes the older one.
   */
  async replaceForUser({ userId, provider, accountEmail, refreshTokenEnc, scopes }) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `DELETE FROM "EmailConnection"
         WHERE "userId" = $1 AND "provider" = $2 AND "accountEmail" <> $3`,
        [userId, provider, accountEmail]
      );
      const res = await client.query(
        `INSERT INTO "EmailConnection"
           ("id", "userId", "provider", "accountEmail", "refreshTokenEnc", "scopes", "createdAt", "updatedAt")
         VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT ("userId", "provider", "accountEmail")
         DO UPDATE SET "refreshTokenEnc" = EXCLUDED."refreshTokenEnc",
                       "scopes" = EXCLUDED."scopes",
                       "updatedAt" = NOW()
         RETURNING ${PUBLIC_COLUMNS}`,
        [userId, provider, accountEmail, refreshTokenEnc, scopes || null]
      );
      await client.query("COMMIT");
      return res.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  },

  async markPushed(id, signatureId) {
    const res = await pool.query(
      `UPDATE "EmailConnection"
       SET "lastPushedAt" = NOW(), "lastSignatureId" = $2, "updatedAt" = NOW()
       WHERE "id" = $1
       RETURNING ${PUBLIC_COLUMNS}`,
      [id, signatureId || null]
    );
    return res.rows[0] || null;
  },

  async deleteById(id) {
    await pool.query(`DELETE FROM "EmailConnection" WHERE "id" = $1`, [id]);
  },

  async deleteByUser(userId, provider) {
    const res = await pool.query(
      `DELETE FROM "EmailConnection" WHERE "userId" = $1 AND "provider" = $2`,
      [userId, provider]
    );
    return res.rowCount;
  },
};

module.exports = emailConnectionRepository;
