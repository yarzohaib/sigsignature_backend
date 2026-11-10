const { Temporal } = require("@js-temporal/polyfill");
const { Pool } = require("pg");
const db = require("../config/prisma");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const User = db.orm.public.User;

const userRepository = {
  async findAll() {
    return User.all();
  },

  async findById(userId) {
    if (!userId) return null;
    const res = await pool.query(`SELECT * FROM "User" WHERE "id" = $1 LIMIT 1`, [userId]);
    return res.rows[0] || null;
  },

  async findFirst(filter) {
    if (filter && filter.id && Object.keys(filter).length === 1) {
      const res = await pool.query(`SELECT * FROM "User" WHERE "id" = $1 LIMIT 1`, [filter.id]);
      return res.rows[0] || null;
    }
    if (filter && filter.email && Object.keys(filter).length === 1) {
      const res = await pool.query(`SELECT * FROM "User" WHERE "email" = $1 LIMIT 1`, [filter.email]);
      return res.rows[0] || null;
    }
    return User.first(filter);
  },

  async create(data) {
    return User.create(data);
  },

  async createMany(data) {
    return User.createAll(data);
  },

  async updateProfile(userId, updateData) {
    const now = Temporal.Now.instant();
    const payload = {
      ...updateData,
      updatedAt: now,
    };
    await User.where({ id: userId }).update(payload);
    return User.first({ id: userId });
  },

  async updatePassword(userId, passwordHash) {
  const query = db.raw.sql`
    UPDATE "User"
    SET
      "password" = ${passwordHash},
      "updatedAt" = NOW()
    WHERE "id" = ${userId}
  `
    .affectedCount()
    .build();

  return db.runtime().execute(query);
},

  async markAsVerified(email) {
    const query = db.raw.sql`
      UPDATE "User"
      SET
        "isVerified" = true,
        "updatedAt" = NOW()
      WHERE "email" = ${email}
    `
      .affectedCount()
      .build();

    return db.runtime().execute(query);
  },

  async clearPasswordAndVerify(userId) {
    const query = db.raw.sql`
      UPDATE "User"
      SET
        "password" = NULL,
        "isVerified" = true,
        "updatedAt" = NOW()
      WHERE "id" = ${userId}
    `
      .affectedCount()
      .build();

    return db.runtime().execute(query);
  },

  async markOnboardingSeen(userId) {
    const now = Temporal.Now.instant();
    await User.where({ id: userId }).update({
      onboardingSeenAt: now,
      updatedAt: now,
    });
    return User.first({ id: userId });
  },

  async findByReferralCode(referralCode) {
    if (!referralCode) return null;
    const cleanCode = referralCode.trim().toUpperCase();
    const res = await pool.query(
      `SELECT * FROM "User" WHERE UPPER("referralCode") = $1 LIMIT 1`,
      [cleanCode]
    );
    return res.rows[0] || null;
  },

  async setReferralCode(userId, code) {
    const res = await pool.query(
      `UPDATE "User"
       SET "referralCode" = $1, "updatedAt" = NOW()
       WHERE "id" = $2
       RETURNING "referralCode"`,
      [code, userId]
    );
    return res.rows[0]?.referralCode || code;
  },

  async setReferredBy(userId, inviterId) {
    const res = await pool.query(
      `UPDATE "User"
       SET "referredById" = $1, "updatedAt" = NOW()
       WHERE "id" = $2 AND "referredById" IS NULL
       RETURNING "id"`,
      [inviterId, userId]
    );
    return res.rowCount;
  },

  async grantProTrialDays(userId, days = 30) {
    const res = await pool.query(
      `UPDATE "User"
       SET
         "proTrialUntil" = (
           CASE
             WHEN "proTrialUntil" IS NOT NULL AND "proTrialUntil" > NOW()
             THEN "proTrialUntil" + ($1 || ' days')::interval
             ELSE NOW() + ($1 || ' days')::interval
           END
         ),
         "referralCount" = COALESCE("referralCount", 0) + 1,
         "updatedAt" = NOW()
       WHERE "id" = $2
       RETURNING "id", "email", "firstName", "referralCode", "proTrialUntil", "referralCount"`,
      [days.toString(), userId]
    );
    return res.rows[0] || null;
  },

  async grantInviteeProTrial(userId, days = 30) {
    const res = await pool.query(
      `UPDATE "User"
       SET
         "proTrialUntil" = (
           CASE
             WHEN "proTrialUntil" IS NOT NULL AND "proTrialUntil" > NOW()
             THEN "proTrialUntil" + ($1 || ' days')::interval
             ELSE NOW() + ($1 || ' days')::interval
           END
         ),
         "updatedAt" = NOW()
       WHERE "id" = $2
       RETURNING "id", "email", "firstName", "referralCode", "proTrialUntil"`,
      [days.toString(), userId]
    );
    return res.rows[0] || null;
  },
};

module.exports = userRepository;