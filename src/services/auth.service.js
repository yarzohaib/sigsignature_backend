const argon2 = require("argon2");
const crypto = require("crypto");
const { Temporal } = require("@js-temporal/polyfill");

const {
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  ConflictError,
  NotFoundError,
} = require("../utils/errors");

const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("../utils/jwt");

const passwordResetRepository = require("../repositories/password-reset.repository");
const sessionRepository = require("../repositories/session.repository");
const userRepository = require("../repositories/user.repository");
const emailVerificationRepository = require("../repositories/email-verification.repository");
const mailService = require("./mail.service");
const referralService = require("./referral.service");
const {
  parseDeviceLabel,
  maskIpAddress,
  resolveCurrentSessionId,
} = require("../utils/sessionHelper");

const RESET_TOKEN_TTL_MINUTES = 30;
const VERIFICATION_TOKEN_TTL_HOURS = 24;

const SESSION_TTL_DAYS = parseInt(process.env.SESSION_TTL_DAYS || "7", 10);
const SESSION_TTL_MS = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;

// Pre-computed fallback Argon2 hash for timing attack mitigation during login
let DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$90l0lC8b+s2iA6g9v7k+P7pQ2t7y8u9w0a1b2c3d4e5";
(async () => {
  try {
    DUMMY_HASH = await argon2.hash("sigsignature-dummy-password-timing-mitigation");
  } catch (_) {}
})();

function hashRefreshToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function hashResetToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function hashVerificationToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function isTokenExpired(expiresAt) {
  if (!expiresAt) return true;
  if (expiresAt instanceof Temporal.Instant) {
    return Temporal.Instant.compare(expiresAt, Temporal.Now.instant()) <= 0;
  }
  const time = new Date(expiresAt).getTime();
  return isNaN(time) || time <= Date.now();
}

async function issueUserSession(user, { userAgent, ipAddress, deviceName } = {}) {
  const refreshToken = generateRefreshToken(user);
  const refreshTokenHash = hashRefreshToken(refreshToken);

  const expiresAt = Temporal.Instant.fromEpochMilliseconds(
    Date.now() + SESSION_TTL_MS
  );

  const session = await sessionRepository.create({
    userId: user.id,
    refreshTokenHash,
    expiresAt,
    userAgent: userAgent || null,
    ipAddress: ipAddress || null,
    deviceName: deviceName || null,
  });

  const accessToken = generateAccessToken(user, session?.id || null);

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
      referralCode: user.referralCode || null,
      proTrialUntil: user.proTrialUntil
        ? typeof user.proTrialUntil.toISOString === "function"
          ? user.proTrialUntil.toISOString()
          : String(user.proTrialUntil)
        : null,
      isProTrialActive,
      referralCount: user.referralCount || 0,
      onboardingSeenAt: user.onboardingSeenAt
        ? typeof user.onboardingSeenAt.toISOString === "function"
          ? user.onboardingSeenAt.toISOString()
          : String(user.onboardingSeenAt)
        : null,
    },
    tokens: {
      accessToken,
      refreshToken,
    },
  };
}

const authService = {
  async signup({ email, password, firstName, lastName, referralCode }) {
    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await userRepository.findFirst({
      email: normalizedEmail,
    });

    if (existingUser) {
      throw new ConflictError("User already exists with this email address");
    }

    const hashedPassword = await argon2.hash(password);

    const user = await userRepository.create({
      email: normalizedEmail,
      password: hashedPassword,
      firstName: firstName.trim(),
      lastName: lastName ? lastName.trim() : null,
      isVerified: false,
    });

    // Auto-generate personal referral code for the new user immediately
    let personalReferralCode = null;
    try {
      personalReferralCode = referralService.generateReferralCode();
      await userRepository.setReferralCode(user.id, personalReferralCode);
    } catch (codeErr) {
      console.warn("[Auth Service] Failed to auto-provision referral code on signup:", codeErr.message || codeErr);
    }

    // Attach referral if a valid referral code was supplied
    if (referralCode) {
      try {
        await referralService.processReferralOnSignup(user.id, referralCode, normalizedEmail);
      } catch (refErr) {
        console.warn("[Auth Service] Failed to link referral code:", refErr.message || refErr);
      }
    }

    // Generate verification token (24-hour expiration)
    try {
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = hashVerificationToken(rawToken);

      const expiresAt = Temporal.Instant.fromEpochMilliseconds(
        Date.now() + VERIFICATION_TOKEN_TTL_HOURS * 60 * 60 * 1000
      );

      await emailVerificationRepository.create({
        userId: user.id,
        tokenHash,
        expiresAt,
      });

      const frontendBase = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
      const verificationUrl = `${frontendBase}/verify?token=${rawToken}`;

      // Send verification email unawaited; signup must not fail if sending fails
      mailService
        .sendVerificationEmail({
          to: user.email,
          firstName: user.firstName,
          actionUrl: verificationUrl,
          expiresIn: `${VERIFICATION_TOKEN_TTL_HOURS} hours`,
        })
        .catch((err) => {
          console.error("[Auth Service] Failed to send verification email on signup:", err.message || err);
        });
    } catch (err) {
      console.error("[Auth Service] Failed to create verification token on signup:", err.message || err);
    }

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      companyName: user.companyName ?? null,
      avatarUrl: user.avatarUrl ?? null,
    };
  },

  async getCurrentUser(userId) {
    const user = await userRepository.findFirst({
      id: userId,
    });

    if (!user) {
      return null;
    }

    // Auto-backfill referral code if missing for existing user
    let userReferralCode = user.referralCode;
    if (!userReferralCode) {
      try {
        userReferralCode = referralService.generateReferralCode();
        await userRepository.setReferralCode(user.id, userReferralCode);
      } catch (backfillErr) {
        console.warn("[Auth Service] Failed to auto-backfill referral code in getCurrentUser:", backfillErr.message || backfillErr);
      }
    }

    const isProTrialActive = Boolean(
      user.proTrialUntil && new Date(user.proTrialUntil).getTime() > Date.now()
    );

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      companyName: user.companyName ?? null,
      avatarUrl: user.avatarUrl ?? null,
      referralCode: userReferralCode || null,
      proTrialUntil: user.proTrialUntil
        ? typeof user.proTrialUntil.toISOString === "function"
          ? user.proTrialUntil.toISOString()
          : String(user.proTrialUntil)
        : null,
      isProTrialActive,
      referralCount: user.referralCount || 0,
      onboardingSeenAt: user.onboardingSeenAt
        ? typeof user.onboardingSeenAt.toISOString === "function"
          ? user.onboardingSeenAt.toISOString()
          : String(user.onboardingSeenAt)
        : null,
      isActive: user.isActive,
      isVerified: user.isVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  },

  issueUserSession,

  /**
   * Login with timing attack mitigation:
   * Runs Argon2 verification regardless of whether the account exists,
   * eliminating timing leaks that reveal registered email addresses.
   */
  async login({ email, password }, context = {}) {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await userRepository.findFirst({
      email: normalizedEmail,
    });

    // Timing attack mitigation: verify against dummy hash if user or password is missing
    const hashToVerify = user && user.password ? user.password : DUMMY_HASH;
    const passwordValid = await argon2.verify(hashToVerify, password).catch(() => false);

    if (!user || !user.password || !passwordValid) {
      throw new UnauthorizedError("Invalid email or password");
    }

    if (!user.isActive) {
      throw new ForbiddenError("User account is inactive. Please contact support.");
    }

    if (!user.isVerified) {
      throw new ForbiddenError("Please verify your email address before logging in.", "EMAIL_NOT_VERIFIED");
    }

    return issueUserSession(user, context);
  },

  async logout(refreshToken) {
    if (!refreshToken) {
      throw new BadRequestError("Refresh token is required");
    }

    let payload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (_) {
      throw new UnauthorizedError("Invalid refresh token");
    }

    if (payload.type !== "refresh") {
      throw new UnauthorizedError("Invalid refresh token");
    }

    const refreshTokenHash = hashRefreshToken(refreshToken);
    const session = await sessionRepository.findByRefreshTokenHash(refreshTokenHash);

    if (!session) {
      throw new NotFoundError("Session not found");
    }

    if (!session.revokedAt) {
      await sessionRepository.revokeById(session.id);
    }

    return { success: true };
  },

  async logoutAll(userId) {
    await sessionRepository.revokeAllByUserId(userId);
    return { success: true };
  },

  async getSessions(userId, req = null) {
    const sessions = await sessionRepository.findByUserId(userId);
    const currentSessionId = req ? resolveCurrentSessionId(req, sessions) : null;

    return sessions.map((session) => ({
      id: session.id,
      userId: session.userId,
      isCurrent: Boolean(currentSessionId && session.id === currentSessionId),
      device: parseDeviceLabel(session.userAgent) || session.deviceName || "Unknown device",
      deviceName: session.deviceName,
      userAgent: session.userAgent,
      ipAddress: maskIpAddress(session.ipAddress),
      lastUsedAt: session.updatedAt || session.createdAt,
      expiresAt: session.expiresAt,
      revokedAt: session.revokedAt,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
    }));
  },

  async revokeSession(userId, sessionId) {
    const session = await sessionRepository.findById(sessionId);

    if (!session || session.userId !== userId) {
      throw new NotFoundError("Session not found");
    }

    if (!session.revokedAt) {
      await sessionRepository.revokeById(session.id);
    }

    return { success: true };
  },

  async revokeOtherSessions(userId, req = null) {
    const sessions = await sessionRepository.findByUserId(userId);
    const currentSessionId = req ? resolveCurrentSessionId(req, sessions) : null;
    const count = await sessionRepository.revokeOthersByUserId(userId, currentSessionId);

    // Send security notification email
    const user = await userRepository.findFirst({ id: userId });
    if (user) {
      const userAgent = req?.headers?.["user-agent"] || "";
      const ip = req?.ip || req?.headers?.["x-forwarded-for"] || "";
      mailService
        .sendSessionsRevokedEmail({
          to: user.email,
          firstName: user.firstName,
          time: new Date().toUTCString(),
          deviceInfo: parseDeviceLabel(userAgent),
          ipAddress: maskIpAddress(ip) || "Unknown IP",
        })
        .catch((err) => {
          console.error(
            "[Auth Service] Failed to send sessions revoked email:",
            err.message || err
          );
        });
    }

    return { count };
  },

  /**
   * Refresh tokens with:
   * 1. Automatic reuse / theft detection (revokes ALL sessions if revoked token is used)
   * 2. Atomic session rotation (prevents race conditions)
   * 3. Preservation and updating of userAgent and ipAddress metadata
   * 4. Configurable session TTL
   */
  async refreshTokens(refreshToken, { userAgent, ipAddress } = {}) {
    if (!refreshToken) {
      throw new BadRequestError("Refresh token is required");
    }

    let payload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (error) {
      console.warn("[Auth Service] Refresh token verification failed:", error.message);
      throw new UnauthorizedError("Invalid refresh token");
    }

    if (payload.type !== "refresh") {
      throw new UnauthorizedError("Invalid refresh token");
    }

    const refreshTokenHash = hashRefreshToken(refreshToken);
    const session = await sessionRepository.findByRefreshTokenHash(refreshTokenHash);

    if (!session) {
      throw new UnauthorizedError("Session not found");
    }

    // THEFT / REUSE DETECTION:
    // If this session was ALREADY revoked, an attacker or victim is attempting reuse!
    // Revoke all active sessions for this user immediately (RFC 6819).
    if (session.revokedAt) {
      console.warn(`[Security Alert] Refresh token reuse detected for userId=${session.userId}. Revoking all active sessions.`);
      await sessionRepository.revokeAllByUserId(session.userId);
      throw new UnauthorizedError("Session has been revoked due to security violation");
    }

    if (isTokenExpired(session.expiresAt)) {
      throw new UnauthorizedError("Session has expired");
    }

    // ATOMIC ROTATION: Revoke active session conditionally (WHERE revokedAt IS NULL)
    const affected = await sessionRepository.revokeIfActive(session.id);
    if (affected !== 1) {
      console.warn(`[Security Alert] Concurrent refresh token reuse detected for userId=${session.userId}. Revoking all sessions.`);
      await sessionRepository.revokeAllByUserId(session.userId);
      throw new UnauthorizedError("Session has been revoked due to concurrent reuse");
    }

    const user = await userRepository.findFirst({
      id: payload.sub,
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedError("User is inactive or does not exist");
    }

    if (!user.isVerified) {
      throw new ForbiddenError("Please verify your email address before continuing.", "EMAIL_NOT_VERIFIED");
    }

    const newRefreshToken = generateRefreshToken(user);
    const newRefreshTokenHash = hashRefreshToken(newRefreshToken);

    const newExpiresAt = Temporal.Instant.fromEpochMilliseconds(
      Date.now() + SESSION_TTL_MS
    );

    // Preserve/update client metadata on rotation
    const newSession = await sessionRepository.create({
      userId: user.id,
      refreshTokenHash: newRefreshTokenHash,
      expiresAt: newExpiresAt,
      userAgent: userAgent || session.userAgent || null,
      ipAddress: ipAddress || session.ipAddress || null,
      deviceName: session.deviceName || null,
    });

    const newAccessToken = generateAccessToken(user, newSession?.id || null);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        companyName: user.companyName ?? null,
      },
    };
  },

  async forgotPassword(email) {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await userRepository.findFirst({
      email: normalizedEmail,
    });

    /*
     * Always return success here.
     * This prevents attackers from discovering which email addresses have accounts.
     */
    if (!user) {
      return { success: true };
    }

    // Invalidate older unused reset tokens for this user
    await passwordResetRepository.invalidateAllUnusedForUser(user.id);

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashResetToken(rawToken);

    // Shared 30-minute expiration
    const expiresAt = Temporal.Instant.fromEpochMilliseconds(
      Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000
    );

    await passwordResetRepository.create({
      userId: user.id,
      tokenHash,
      expiresAt,
    });

    const frontendBase = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
    const resetUrl = `${frontendBase}/reset?token=${rawToken}`;

    // Send email unawaited, never log link or token
    mailService
      .sendPasswordResetEmail({
        to: user.email,
        firstName: user.firstName,
        actionUrl: resetUrl,
        expiresIn: `${RESET_TOKEN_TTL_MINUTES} minutes`,
      })
      .catch((err) => {
        console.error("[Auth Service] Failed to send password reset email:", err);
      });

    return { success: true };
  },

  async validateResetToken(token) {
    if (!token) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    const tokenHash = hashResetToken(token.trim());
    const resetToken = await passwordResetRepository.findByTokenHash(tokenHash);

    if (!resetToken || resetToken.usedAt || isTokenExpired(resetToken.expiresAt)) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    const user = await userRepository.findFirst({
      id: resetToken.userId,
    });

    if (!user || !user.isActive) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    return { valid: true };
  },

  async resetPassword(token, newPassword) {
    if (!token) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    if (!newPassword) {
      throw new BadRequestError("New password is required");
    }

    const tokenHash = hashResetToken(token.trim());
    const resetToken = await passwordResetRepository.findByTokenHash(tokenHash);

    if (!resetToken || resetToken.usedAt || isTokenExpired(resetToken.expiresAt)) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    const user = await userRepository.findFirst({
      id: resetToken.userId,
    });

    if (!user || !user.isActive) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    // Mark as used FIRST atomically and verify affected count is exactly 1
    const rawAffectedCount = await passwordResetRepository.markAsUsed(resetToken.id);
    const affectedCount = typeof rawAffectedCount === "number"
      ? rawAffectedCount
      : (rawAffectedCount?.affectedRows ?? rawAffectedCount?.rowCount ?? 0);

    if (affectedCount !== 1) {
      throw new BadRequestError("Invalid or expired reset token");
    }

    const passwordHash = await argon2.hash(newPassword);
    await userRepository.updatePassword(user.id, passwordHash);

    // Password change invalidates all existing sessions
    await sessionRepository.revokeAllByUserId(user.id);

    return { success: true };
  },

  async requestEmailVerification(email) {
    const genericResponse = {
      success: true,
      message: "If an account exists for this email, a verification link has been generated",
    };

    if (!email) {
      return genericResponse;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await userRepository.findFirst({
      email: normalizedEmail,
    });

    if (!user || user.isVerified) {
      return genericResponse;
    }

    // Invalidate older unused verification tokens for this user
    await emailVerificationRepository.invalidateAllUnusedForUser(user.id);

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashVerificationToken(rawToken);

    const expiresAt = Temporal.Instant.fromEpochMilliseconds(
      Date.now() + VERIFICATION_TOKEN_TTL_HOURS * 60 * 60 * 1000
    );

    await emailVerificationRepository.create({
      userId: user.id,
      tokenHash,
      expiresAt,
    });

    const frontendBase = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
    const verificationUrl = `${frontendBase}/verify?token=${rawToken}`;

    mailService
      .sendVerificationEmail({
        to: user.email,
        firstName: user.firstName,
        actionUrl: verificationUrl,
        expiresIn: `${VERIFICATION_TOKEN_TTL_HOURS} hours`,
      })
      .catch((err) => {
        console.error("[Auth Service] Failed to send verification email on request:", err);
      });

    return genericResponse;
  },

  async verifyEmailToken(token) {
    const INVALID_TOKEN_MESSAGE = "Invalid or expired verification token";

    if (!token) {
      throw new BadRequestError(INVALID_TOKEN_MESSAGE);
    }

    const tokenHash = hashVerificationToken(token.trim());
    const record = await emailVerificationRepository.findByTokenHash(tokenHash);

    if (!record || record.usedAt || isTokenExpired(record.expiresAt)) {
      throw new BadRequestError(INVALID_TOKEN_MESSAGE);
    }

    const user = await userRepository.findFirst({
      id: record.userId,
    });

    if (!user) {
      throw new BadRequestError(INVALID_TOKEN_MESSAGE);
    }

    const rawAffectedCount = await emailVerificationRepository.markAsUsed(record.id);
    const affectedCount = typeof rawAffectedCount === "number"
      ? rawAffectedCount
      : (rawAffectedCount?.affectedRows ?? rawAffectedCount?.rowCount ?? 0);

    if (affectedCount !== 1) {
      throw new BadRequestError(INVALID_TOKEN_MESSAGE);
    }

    await userRepository.markAsVerified(user.email);

    // If this verified user was referred, immediately unlock 30 days of Pro for both parties
    try {
      await referralService.activateReferralRewards(user.id);
    } catch (refErr) {
      console.warn("[Auth Service] Failed to activate referral rewards on verification:", refErr.message || refErr);
    }

    return {
      success: true,
      message: "Email verified successfully",
    };
  },
};

module.exports = authService;