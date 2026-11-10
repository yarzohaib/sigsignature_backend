const argon2 = require("argon2");
const { Pool } = require("pg");
const userRepository = require("../repositories/user.repository");
const userSettingsRepository = require("../repositories/user-settings.repository");
const oauthAccountRepository = require("../repositories/oauth-account.repository");
const signatureRepository = require("../repositories/signature.repository");
const teamRepository = require("../repositories/team.repository");
const sessionRepository = require("../repositories/session.repository");
const mailService = require("./mail.service");
const { NotFoundError, BadRequestError } = require("../utils/errors");
const {
  parseDeviceLabel,
  maskIpAddress,
  resolveCurrentSessionId,
} = require("../utils/sessionHelper");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const DEFAULT_SETTINGS = {
  defaultTemplateId: null,
  defaultExportFormat: "html",
  signatureFont: "Arimo",
  brandColor: "#245FD4",
  includePhoto: true,
  notifyProductUpdates: true,
  notifyTips: false,
  premiumWaitlistAt: null,
};

function formatIso(val) {
  if (!val) return null;
  if (typeof val.toISOString === "function") {
    return val.toISOString();
  }
  return String(val);
}

function formatSettings(settingsRow) {
  if (!settingsRow) {
    return {
      ...DEFAULT_SETTINGS,
      createdAt: null,
      updatedAt: null,
    };
  }

  return {
    defaultTemplateId: settingsRow.defaultTemplateId ?? DEFAULT_SETTINGS.defaultTemplateId,
    defaultExportFormat: settingsRow.defaultExportFormat ?? DEFAULT_SETTINGS.defaultExportFormat,
    signatureFont: settingsRow.signatureFont ?? DEFAULT_SETTINGS.signatureFont,
    brandColor: settingsRow.brandColor ?? DEFAULT_SETTINGS.brandColor,
    includePhoto:
      typeof settingsRow.includePhoto === "boolean"
        ? settingsRow.includePhoto
        : DEFAULT_SETTINGS.includePhoto,
    notifyProductUpdates:
      typeof settingsRow.notifyProductUpdates === "boolean"
        ? settingsRow.notifyProductUpdates
        : DEFAULT_SETTINGS.notifyProductUpdates,
    notifyTips:
      typeof settingsRow.notifyTips === "boolean"
        ? settingsRow.notifyTips
        : DEFAULT_SETTINGS.notifyTips,
    premiumWaitlistAt: formatIso(settingsRow.premiumWaitlistAt),
    createdAt: formatIso(settingsRow.createdAt),
    updatedAt: formatIso(settingsRow.updatedAt),
  };
}

const accountService = {
  /**
   * Get full account details for the authenticated user.
   */
  async getAccount(userId) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const hasPassword = Boolean(
      user.password && typeof user.password === "string" && user.password.trim() !== ""
    );

    const oauthAccounts = await oauthAccountRepository.findByUserId(userId);
    const providers = Array.from(new Set(oauthAccounts.map((a) => a.provider)));

    const settingsRow = await userSettingsRepository.findByUserId(userId);
    const settings = formatSettings(settingsRow);

    const signatureCount = await signatureRepository.countByUser(userId);
    const lifetimeCount = await signatureRepository.lifetimeCountByUser(userId);
    const signatureLimit = Number(process.env.SIGNATURE_LIMIT_PER_USER || 3);

    const isProTrialActive = Boolean(
      user.proTrialUntil && new Date(user.proTrialUntil).getTime() > Date.now()
    );

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        companyName: user.companyName ?? null,
        avatarUrl: user.avatarUrl ?? null,
        isVerified: user.isVerified,
        onboardingSeenAt: formatIso(user.onboardingSeenAt),
        referralCode: user.referralCode || null,
        proTrialUntil: formatIso(user.proTrialUntil),
        isProTrialActive,
        referralCount: user.referralCount || 0,
      },
      hasPassword,
      providers,
      settings,
      usage: {
        signatures: Math.min(signatureLimit, Math.max(signatureCount, lifetimeCount)),
        activeSignatures: signatureCount,
        lifetimeCreated: lifetimeCount,
        signatureLimit,
      },
    };
  },

  /**
   * Update profile fields (firstName, lastName, companyName, avatarUrl).
   * Strips unknown keys, ignores email silently.
   */
  async updateProfile(userId, updateData) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const payload = {};
    if (updateData.firstName !== undefined) {
      payload.firstName = updateData.firstName.trim();
    }
    if (updateData.lastName !== undefined) {
      payload.lastName = updateData.lastName ? updateData.lastName.trim() : null;
    }
    if (updateData.companyName !== undefined) {
      payload.companyName = updateData.companyName ? updateData.companyName.trim() : null;
    }
    if (updateData.avatarUrl !== undefined) {
      payload.avatarUrl = updateData.avatarUrl ? updateData.avatarUrl.trim() : null;
    }

    const updatedUser = await userRepository.updateProfile(userId, payload);

    return {
      id: updatedUser.id,
      email: updatedUser.email,
      firstName: updatedUser.firstName,
      lastName: updatedUser.lastName,
      companyName: updatedUser.companyName ?? null,
      avatarUrl: updatedUser.avatarUrl ?? null,
      isVerified: updatedUser.isVerified,
    };
  },

  /**
   * Upsert user settings.
   */
  async updateSettings(userId, settingsData) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const updatedRow = await userSettingsRepository.upsert(userId, settingsData);
    return formatSettings(updatedRow);
  },

  /**
   * Join premium waitlist (idempotent).
   */
  async joinWaitlist(userId) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const updatedRow = await userSettingsRepository.joinWaitlist(userId);
    return formatSettings(updatedRow);
  },

  /**
   * Mark onboarding modal as seen (idempotent).
   */
  async markOnboardingSeen(userId) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const updatedUser = await userRepository.markOnboardingSeen(userId);
    return {
      onboardingSeenAt: formatIso(updatedUser.onboardingSeenAt),
    };
  },

  /**
   * POST /api/v1/account/password
   * Change user password, revoke all OTHER sessions, and send a security email.
   */
  async changePassword(userId, { currentPassword, newPassword }, req = null) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    if (!user.password || user.password.trim() === "") {
      throw new BadRequestError(
        "No password is set on this account. Please use OAuth to sign in.",
        "NO_PASSWORD_SET"
      );
    }

    const isMatch = await argon2.verify(user.password, currentPassword).catch(() => false);
    if (!isMatch) {
      throw new BadRequestError("Invalid current password", "INVALID_CURRENT_PASSWORD");
    }

    if (currentPassword === newPassword) {
      throw new BadRequestError(
        "New password must differ from current password",
        "PASSWORD_UNCHANGED"
      );
    }

    const hashedPassword = await argon2.hash(newPassword);
    await userRepository.updatePassword(userId, hashedPassword);

    // Revoke all OTHER sessions, keeping the current session
    const sessions = await sessionRepository.findByUserId(userId);
    const currentSessionId = req ? resolveCurrentSessionId(req, sessions) : null;
    await sessionRepository.revokeOthersByUserId(userId, currentSessionId);

    // Send security notification email (failure must never fail request)
    const userAgent = req?.headers?.["user-agent"] || "";
    const ip = req?.ip || req?.headers?.["x-forwarded-for"] || "";
    mailService
      .sendPasswordChangedEmail({
        to: user.email,
        firstName: user.firstName,
        time: new Date().toUTCString(),
        deviceInfo: parseDeviceLabel(userAgent),
        ipAddress: maskIpAddress(ip) || "Unknown IP",
      })
      .catch((err) => {
        console.error(
          "[Account Service] Failed to send password changed email:",
          err.message || err
        );
      });

    return {
      success: true,
      message: "Password changed successfully",
    };
  },

  /**
   * GET /api/v1/account/export
   * Generates a complete JSON document of account data with NO passwords or token hashes.
   */
  async exportAccount(userId) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const settingsRow = await userSettingsRepository.findByUserId(userId);
    const settings = formatSettings(settingsRow);

    const signatures = await signatureRepository.listByUser(userId);
    const exportedSignatures = (signatures || []).map((sig) => ({
      name: sig.name,
      templateId: sig.templateId,
      templateVersion: sig.templateVersion,
      data: sig.data,
      createdAt: formatIso(sig.createdAt),
      updatedAt: formatIso(sig.updatedAt),
    }));

    const teamWithMembers = await teamRepository.getWithMembersByOwner(userId);
    let teamExport = null;
    if (teamWithMembers) {
      teamExport = {
        name: teamWithMembers.name,
        kind: teamWithMembers.kind,
        templateId: teamWithMembers.templateId,
        templateVersion: teamWithMembers.templateVersion,
        data: teamWithMembers.data,
        memberLimit: teamWithMembers.memberLimit,
        createdAt: formatIso(teamWithMembers.createdAt),
        updatedAt: formatIso(teamWithMembers.updatedAt),
        members: (teamWithMembers.members || []).map((m) => ({
          name: m.name,
          email: m.email,
          jobTitle: m.jobTitle,
          phone: m.phone,
          photoUrl: m.photoUrl,
          socials: m.socials,
          status: m.status,
          sentAt: formatIso(m.sentAt),
          acceptedAt: formatIso(m.acceptedAt),
          sendCount: m.sendCount,
          createdAt: formatIso(m.createdAt),
          updatedAt: formatIso(m.updatedAt),
          // Crucial security: tokenHash and tokenExpiresAt are NEVER exported
        })),
      };
    }

    return {
      exportedAt: new Date().toISOString(),
      profile: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        companyName: user.companyName ?? null,
        isVerified: user.isVerified,
        createdAt: formatIso(user.createdAt),
        updatedAt: formatIso(user.updatedAt),
      },
      settings,
      signatures: exportedSignatures,
      team: teamExport,
    };
  },

  /**
   * DELETE /api/v1/account
   * Permanently deletes account and all related records in one transaction.
   * Logs ONLY user id (never email, password, or tokens).
   */
  async deleteAccount(userId, { password, confirm } = {}) {
    const user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    const hasPassword = Boolean(
      user.password && typeof user.password === "string" && user.password.trim() !== ""
    );

    if (hasPassword) {
      if (!password || typeof password !== "string") {
        throw new BadRequestError(
          "Password is required to delete your account",
          "INVALID_PASSWORD"
        );
      }
      const isValid = await argon2.verify(user.password, password).catch(() => false);
      if (!isValid) {
        throw new BadRequestError("Invalid password", "INVALID_PASSWORD");
      }
    } else {
      if (confirm !== "DELETE") {
        throw new BadRequestError(
          "Confirmation required. Please provide confirm: 'DELETE'",
          "CONFIRMATION_REQUIRED"
        );
      }
    }

    // Atomic transaction deleting user and all cascading owned data
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `DELETE FROM "TeamMember" WHERE "teamId" IN (SELECT "id" FROM "Team" WHERE "ownerId" = $1)`,
        [userId]
      );
      await client.query(`DELETE FROM "Team" WHERE "ownerId" = $1`, [userId]);
      await client.query(`DELETE FROM "Signature" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "UserSettings" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "OAuthAccount" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "OAuthLoginCode" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "PasswordResetToken" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "EmailVerificationToken" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "Session" WHERE "userId" = $1`, [userId]);
      await client.query(`DELETE FROM "User" WHERE "id" = $1`, [userId]);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }

    // Log ONLY user ID, never email, password, or tokens
    console.log(`[Account Service] Account permanently deleted for userId=${userId}`);

    // Send final "Your account was deleted" email after transaction commits (failure ignored)
    mailService
      .sendAccountDeletedEmail({
        to: user.email,
        firstName: user.firstName,
      })
      .catch((err) => {
        console.error(
          "[Account Service] Failed to send account deleted email:",
          err.message || err
        );
      });

    return { success: true };
  },
};

module.exports = {
  accountService,
  DEFAULT_SETTINGS,
  formatSettings,
};
