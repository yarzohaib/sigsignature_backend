const { Temporal } = require("@js-temporal/polyfill");
const db = require("../config/prisma");

const Signature = db.orm.public.Signature;

const signatureRepository = {
  /**
   * List all active (non-deleted) signatures for a user, newest updatedAt first.
   * Every query filters strictly by userId.
   */
  async listByUser(userId) {
    const all = await Signature.where({ userId })
      .orderBy((s) => s.updatedAt.desc())
      .all();
    return all.filter((s) => !s.data || !s.data._deleted);
  },

  /**
   * Find a specific signature by id and userId.
   * Returns null if signature is deleted or does not belong to user.
   */
  async findByIdForUser(id, userId) {
    const s = await Signature.where({ id, userId }).first();
    if (!s || (s.data && s.data._deleted)) {
      return null;
    }
    return s;
  },

  /**
   * Count active (non-deleted) signatures owned by a user.
   */
  async countByUser(userId) {
    const active = await this.listByUser(userId);
    return active.length;
  },

  /**
   * Count all signatures created by a user over lifetime (including deleted).
   */
  async lifetimeCountByUser(userId) {
    const all = await Signature.where({ userId }).all();
    return all.length;
  },

  /**
   * Create a new signature for a user.
   */
  async create({ userId, name, templateId, templateVersion = 1, data }) {
    return Signature.create({
      userId,
      name,
      templateId,
      templateVersion,
      data,
    });
  },

  /**
   * Update an existing signature owned by a user.
   * Automatically refreshes updatedAt timestamp.
   */
  async update(id, userId, updateData) {
    const now = Temporal.Now.instant();
    const payload = {
      ...updateData,
      updatedAt: now,
    };
    return Signature.where({ id, userId }).update(payload);
  },

  /**
   * Delete a signature owned by a user.
   * Soft-deletes by marking _deleted: true inside data so lifetime creation limits persist.
   */
  async delete(id, userId) {
    const existing = await Signature.where({ id, userId }).first();
    if (!existing) return null;
    const now = Temporal.Now.instant();
    const existingData =
      typeof existing.data === "object" && existing.data !== null ? existing.data : {};
    const updatedData = {
      ...existingData,
      _deleted: true,
      deletedAt: new Date().toISOString(),
    };
    return Signature.where({ id, userId }).update({
      data: updatedData,
      updatedAt: now,
    });
  },
};

module.exports = signatureRepository;
