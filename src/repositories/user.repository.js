const { Temporal } = require("@js-temporal/polyfill");
const db = require("../config/prisma");

const User = db.orm.public.User;

const userRepository = {
  async findAll() {
    return User.all();
  },

  async findFirst(filter) {
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
};

module.exports = userRepository;