const signatureRepository = require("../repositories/signature.repository");
const { NotFoundError, ForbiddenError } = require("../utils/errors");
const { sanitizeSignature } = require("../utils/plainText");
const { mirrorProviderAvatar } = require("./upload.service");
const { isTrustedProviderAvatarUrl } = require("../validators/signature.validator");

/**
 * If the avatar is a Google or GitHub profile photo, copy it into our own storage and
 * swap in the hosted URL. Keeps the original URL if the copy fails.
 */
async function withHostedAvatar(userId, data) {
  if (!data || typeof data !== "object") return data;
  const avatar = data.avatarUrl;
  if (typeof avatar !== "string" || !isTrustedProviderAvatarUrl(avatar)) return data;
  const hosted = await mirrorProviderAvatar({ userId, url: avatar });
  return hosted ? { ...data, avatarUrl: hosted } : data;
}

const signatureService = {
  /**
   * List all signatures for the authenticated user.
   * Sanitizes text fields on read to neutralize any legacy/unvalidated stored HTML tags.
   */
  async list(userId) {
    const signatures = await signatureRepository.listByUser(userId);
    return Array.isArray(signatures) ? signatures.map(sanitizeSignature) : signatures;
  },

  /**
   * Total signatures created over lifetime by the user.
   */
  async lifetimeCount(userId) {
    return signatureRepository.lifetimeCountByUser(userId);
  },

  /**
   * Get a single signature by id for the authenticated user.
   * Throws 404 if signature does not exist or belongs to another user.
   * Sanitizes text fields on read to neutralize any legacy/unvalidated stored HTML tags.
   */
  async get(id, userId) {
    const signature = await signatureRepository.findByIdForUser(id, userId);
    if (!signature) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }
    return sanitizeSignature(signature);
  },

  /**
   * Create a new signature for the authenticated user.
   * Enforces the account lifetime plan limit (SIGNATURE_LIMIT_PER_USER) for Free users.
   * Pro / Premium users (including active Pro trial) have unlimited creations.
   */
  async create(userId, { name, templateId, templateVersion, data }) {
    const user = await userRepository.findFirst({ id: userId });
    const isPro = Boolean(
      user && user.proTrialUntil && new Date(user.proTrialUntil).getTime() > Date.now()
    );

    if (!isPro) {
      const limit = Number(process.env.SIGNATURE_LIMIT_PER_USER || 3);
      const lifetimeCount = await signatureRepository.lifetimeCountByUser(userId);

      if (lifetimeCount >= limit) {
        throw new ForbiddenError(
          `You have reached the maximum signature limit (${limit}) for your Free account. Deleting signatures does not grant additional slots. Please upgrade your plan.`,
          "SIGNATURE_LIMIT_REACHED"
        );
      }
    }

    const hostedData = await withHostedAvatar(userId, data);

    const created = await signatureRepository.create({
      userId,
      name,
      templateId,
      templateVersion,
      data: hostedData,
    });
    return sanitizeSignature(created);
  },

  /**
   * Update an existing signature for the authenticated user.
   * Throws 404 if signature does not exist or belongs to another user.
   */
  async update(id, userId, updateData) {
    const existing = await signatureRepository.findByIdForUser(id, userId);
    if (!existing) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }

    const payload = { ...updateData };
    if (updateData.data && typeof updateData.data === "object") {
      updateData = { ...updateData, data: await withHostedAvatar(userId, updateData.data) };
      payload.data = updateData.data;
    }
    if (updateData.data && typeof updateData.data === "object") {
      const existingData =
        typeof existing.data === "object" && existing.data !== null
          ? existing.data
          : {};
      payload.data = {
        ...existingData,
        ...updateData.data,
      };

      // Strict Identity Lock: Prevent modifying Full Name and Company Name on saved signatures
      if (existingData.fullName) {
        payload.data.fullName = existingData.fullName;
      }
      if (existingData.companyName !== undefined) {
        payload.data.companyName = existingData.companyName;
      }

      // If Studio format with canvas elements, also preserve the bound/original name and company text elements
      if (Array.isArray(existingData.elements) && Array.isArray(payload.data.elements)) {
        const origNameEl = existingData.elements.find(
          (el) => el.type === "text" && (el.bind === "name" || el.id === "el-name")
        );
        const origCompanyEl = existingData.elements.find(
          (el) => el.type === "text" && (el.bind === "company" || el.id === "el-company")
        );

        if (origNameEl || origCompanyEl) {
          payload.data.elements = payload.data.elements.map((el) => {
            if (origNameEl && el.id === origNameEl.id) {
              return { ...el, text: origNameEl.text };
            }
            if (origCompanyEl && el.id === origCompanyEl.id) {
              return { ...el, text: origCompanyEl.text };
            }
            return el;
          });
        }
      }

      if (
        updateData.data.socials &&
        typeof updateData.data.socials === "object" &&
        existingData.socials
      ) {
        payload.data.socials = {
          ...existingData.socials,
          ...updateData.data.socials,
        };
      }
      if (
        updateData.data.optional &&
        typeof updateData.data.optional === "object" &&
        existingData.optional
      ) {
        payload.data.optional = {
          ...existingData.optional,
          ...updateData.data.optional,
        };
      }
    }

    const updated = await signatureRepository.update(id, userId, payload);
    if (!updated || !updated.id) {
      const refreshed = await signatureRepository.findByIdForUser(id, userId);
      return sanitizeSignature(refreshed);
    }
    return sanitizeSignature(updated);
  },

  /**
   * Remove a signature for the authenticated user.
   * Throws 404 if signature does not exist or belongs to another user.
   */
  async remove(id, userId) {
    const existing = await signatureRepository.findByIdForUser(id, userId);
    if (!existing) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }

    await signatureRepository.delete(id, userId);
    return true;
  },

  /**
   * Duplicate an existing signature with a new ID and name `${name} (Copy)`.
   * Enforces the account lifetime plan limit (SIGNATURE_LIMIT_PER_USER) for Free users.
   * Pro / Premium users (including active Pro trial) have unlimited creations.
   */
  async duplicate(id, userId) {
    const user = await userRepository.findFirst({ id: userId });
    const isPro = Boolean(
      user && user.proTrialUntil && new Date(user.proTrialUntil).getTime() > Date.now()
    );

    if (!isPro) {
      const limit = Number(process.env.SIGNATURE_LIMIT_PER_USER || 3);
      const lifetimeCount = await signatureRepository.lifetimeCountByUser(userId);

      if (lifetimeCount >= limit) {
        throw new ForbiddenError(
          `You have reached the maximum signature limit (${limit}) for your Free account. Deleting signatures does not grant additional slots. Please upgrade your plan.`,
          "SIGNATURE_LIMIT_REACHED"
        );
      }
    }

    const original = await signatureRepository.findByIdForUser(id, userId);
    if (!original) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }

    const duplicateName = `${original.name} (Copy)`.slice(0, 100);

    const duplicated = await signatureRepository.create({
      userId,
      name: duplicateName,
      templateId: original.templateId,
      templateVersion: original.templateVersion,
      data: original.data,
    });
    return sanitizeSignature(duplicated);
  },
};

module.exports = signatureService;



// const signatureRepository = require("../repositories/signature.repository");
// const { NotFoundError, ForbiddenError } = require("../utils/errors");
// const { sanitizeSignature } = require("../utils/plainText");

// const signatureService = {
//   /**
//    * List all signatures for the authenticated user.
//    * Sanitizes text fields on read to neutralize any legacy/unvalidated stored HTML tags.
//    */
//   async list(userId) {
//     const signatures = await signatureRepository.listByUser(userId);
//     return Array.isArray(signatures) ? signatures.map(sanitizeSignature) : signatures;
//   },

//   /**
//    * Get a single signature by id for the authenticated user.
//    * Throws 404 if signature does not exist or belongs to another user.
//    * Sanitizes text fields on read to neutralize any legacy/unvalidated stored HTML tags.
//    */
//   async get(id, userId) {
//     const signature = await signatureRepository.findByIdForUser(id, userId);
//     if (!signature) {
//       throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
//     }
//     return sanitizeSignature(signature);
//   },

//   /**
//    * Create a new signature for the authenticated user.
//    * Enforces the account plan limit (SIGNATURE_LIMIT_PER_USER).
//    */
//   async create(userId, { name, templateId, templateVersion, data }) {
//     const limit = Number(process.env.SIGNATURE_LIMIT_PER_USER || 3);
//     const count = await signatureRepository.countByUser(userId);

//     if (count >= limit) {
//       throw new ForbiddenError(
//         `You have reached the maximum signature limit (${limit}) for your account. Please delete an existing signature or upgrade your plan.`,
//         "SIGNATURE_LIMIT_REACHED"
//       );
//     }

//     const created = await signatureRepository.create({
//       userId,
//       name,
//       templateId,
//       templateVersion,
//       data,
//     });
//     return sanitizeSignature(created);
//   },

//   /**
//    * Update an existing signature for the authenticated user.
//    * Throws 404 if signature does not exist or belongs to another user.
//    */
//   async update(id, userId, updateData) {
//     const existing = await signatureRepository.findByIdForUser(id, userId);
//     if (!existing) {
//       throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
//     }

//     const payload = { ...updateData };
//     if (updateData.data && typeof updateData.data === "object") {
//       const existingData =
//         typeof existing.data === "object" && existing.data !== null
//           ? existing.data
//           : {};
//       payload.data = {
//         ...existingData,
//         ...updateData.data,
//       };
//       if (
//         updateData.data.socials &&
//         typeof updateData.data.socials === "object" &&
//         existingData.socials
//       ) {
//         payload.data.socials = {
//           ...existingData.socials,
//           ...updateData.data.socials,
//         };
//       }
//       if (
//         updateData.data.optional &&
//         typeof updateData.data.optional === "object" &&
//         existingData.optional
//       ) {
//         payload.data.optional = {
//           ...existingData.optional,
//           ...updateData.data.optional,
//         };
//       }
//     }

//     const updated = await signatureRepository.update(id, userId, payload);
//     if (!updated || !updated.id) {
//       const refreshed = await signatureRepository.findByIdForUser(id, userId);
//       return sanitizeSignature(refreshed);
//     }
//     return sanitizeSignature(updated);
//   },

//   /**
//    * Remove a signature for the authenticated user.
//    * Throws 404 if signature does not exist or belongs to another user.
//    */
//   async remove(id, userId) {
//     const existing = await signatureRepository.findByIdForUser(id, userId);
//     if (!existing) {
//       throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
//     }

//     await signatureRepository.delete(id, userId);
//     return true;
//   },

//   /**
//    * Duplicate an existing signature with a new ID and name `${name} (Copy)`.
//    * Enforces the account plan limit (SIGNATURE_LIMIT_PER_USER).
//    */
//   async duplicate(id, userId) {
//     const limit = Number(process.env.SIGNATURE_LIMIT_PER_USER || 3);
//     const count = await signatureRepository.countByUser(userId);

//     if (count >= limit) {
//       throw new ForbiddenError(
//         `You have reached the maximum signature limit (${limit}) for your account. Please delete an existing signature or upgrade your plan.`,
//         "SIGNATURE_LIMIT_REACHED"
//       );
//     }

//     const original = await signatureRepository.findByIdForUser(id, userId);
//     if (!original) {
//       throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
//     }

//     const duplicateName = `${original.name} (Copy)`.slice(0, 100);

//     const duplicated = await signatureRepository.create({
//       userId,
//       name: duplicateName,
//       templateId: original.templateId,
//       templateVersion: original.templateVersion,
//       data: original.data,
//     });
//     return sanitizeSignature(duplicated);
//   },
// };

// module.exports = signatureService;
