const signatureService = require("../services/signature.service");

/**
 * Formats signature record to ensure consistent output format:
 * { id, name, templateId, templateVersion, data, createdAt, updatedAt }
 */
function formatSignature(sig) {
  if (!sig) return null;
  return {
    id: sig.id,
    name: sig.name,
    templateId: sig.templateId,
    templateVersion: sig.templateVersion,
    data: sig.data,
    createdAt:
      typeof sig.createdAt?.toISOString === "function"
        ? sig.createdAt.toISOString()
        : String(sig.createdAt),
    updatedAt:
      typeof sig.updatedAt?.toISOString === "function"
        ? sig.updatedAt.toISOString()
        : String(sig.updatedAt),
  };
}

const signatureController = {
  /**
   * GET /api/v1/signatures
   * List all signatures for the authenticated user.
   */
  async list(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const signatures = await signatureService.list(userId);
      const lifetimeCreated = await signatureService.lifetimeCount(userId);

      return res.status(200).json({
        success: true,
        data: signatures.map(formatSignature),
        meta: {
          total: signatures.length,
          lifetimeCreated,
          limit: Number(process.env.SIGNATURE_LIMIT_PER_USER || 3),
        },
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/signatures/:id
   * Get a single signature by ID.
   */
  async get(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const { id } = req.params;
      const signature = await signatureService.get(id, userId);

      return res.status(200).json({
        success: true,
        data: formatSignature(signature),
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/signatures
   * Create a new signature.
   */
  async create(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const { name, templateId, templateVersion, data } = req.body;

      const signature = await signatureService.create(userId, {
        name,
        templateId,
        templateVersion,
        data,
      });

      return res.status(201).json({
        success: true,
        message: "Signature created successfully",
        data: formatSignature(signature),
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/signatures/:id
   * Update an existing signature.
   */
  async update(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const { id } = req.params;

      const updated = await signatureService.update(id, userId, req.body);

      return res.status(200).json({
        success: true,
        message: "Signature updated successfully",
        data: formatSignature(updated),
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * DELETE /api/v1/signatures/:id
   * Delete a signature.
   */
  async remove(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const { id } = req.params;

      await signatureService.remove(id, userId);

      return res.status(200).json({
        success: true,
        message: "Signature deleted successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/signatures/:id/duplicate
   * Duplicate an existing signature.
   */
  async duplicate(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const { id } = req.params;

      const duplicated = await signatureService.duplicate(id, userId);

      return res.status(201).json({
        success: true,
        message: "Signature duplicated successfully",
        data: formatSignature(duplicated),
      });
    } catch (error) {
      next(error);
    }
  },
};

module.exports = signatureController;
