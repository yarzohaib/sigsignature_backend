const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const gmailService = require("./gmail.service");
const oauthService = require("./oauth.service");
const tokenCrypto = require("../utils/tokenCrypto");
const emailConnectionRepository = require("../repositories/email-connection.repository");
const signatureRepository = require("../repositories/signature.repository");
const { sanitizeFrontendOrigin } = require("../utils/frontendOrigin");
const { AppError, BadRequestError, NotFoundError } = require("../utils/errors");

const PROVIDER_GMAIL = "gmail";
const STATE_AUDIENCE = "sigsignature-gmail-connect";
const STATE_TTL = "10m";
const RETURN_PATH = "/settings";

function ensureConfigured() {
  if (!gmailService.isConfigured() || !tokenCrypto.isConfigured()) {
    throw new AppError("Gmail integration is not configured on this server.", 503, "GMAIL_NOT_CONFIGURED");
  }
}

function signState({ userId, frontendOrigin }) {
  return jwt.sign(
    { type: "gmail_connect", sub: userId, origin: frontendOrigin, nonce: crypto.randomBytes(12).toString("hex") },
    process.env.JWT_ACCESS_SECRET,
    {
      algorithm: "HS256",
      issuer: process.env.JWT_ISSUER || "sigsignature.com",
      audience: STATE_AUDIENCE,
      expiresIn: STATE_TTL,
    }
  );
}

function verifyState(state) {
  try {
    const payload = jwt.verify(String(state || ""), process.env.JWT_ACCESS_SECRET, {
      algorithms: ["HS256"],
      issuer: process.env.JWT_ISSUER || "sigsignature.com",
      audience: STATE_AUDIENCE,
    });
    if (payload.type !== "gmail_connect" || !payload.sub) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function formatConnection(connection) {
  if (!connection) return null;
  return {
    provider: connection.provider,
    accountEmail: connection.accountEmail,
    lastPushedAt: connection.lastPushedAt ? new Date(connection.lastPushedAt).toISOString() : null,
    lastSignatureId: connection.lastSignatureId || null,
    connectedAt: connection.createdAt ? new Date(connection.createdAt).toISOString() : null,
  };
}

function buildReturnUrl(origin, status, extra = {}) {
  const base = sanitizeFrontendOrigin(origin) || oauthService.getFrontendUrl();
  const url = new URL(RETURN_PATH, base);
  url.searchParams.set("integration", "gmail");
  url.searchParams.set("status", status);
  Object.entries(extra).forEach(([key, value]) => url.searchParams.set(key, value));
  return url.toString();
}

const integrationService = {
  PROVIDER_GMAIL,
  signState,
  verifyState,

  async getGmailStatus(userId) {
    const configured = gmailService.isConfigured() && tokenCrypto.isConfigured();
    const connections = await emailConnectionRepository.findByUser(userId, PROVIDER_GMAIL);
    const connection = connections[0] || null;
    return {
      configured,
      connected: Boolean(connection),
      connection: formatConnection(connection),
    };
  },

  async startGmailConnect({ userId, email, frontendOrigin, req }) {
    ensureConfigured();
    const origin = sanitizeFrontendOrigin(frontendOrigin) || sanitizeFrontendOrigin(req?.headers?.origin);
    if (!origin) {
      throw new BadRequestError("Could not tell which site to return to after connecting Gmail.", "GMAIL_BAD_ORIGIN");
    }
    const state = signState({ userId, frontendOrigin: origin });
    const url = gmailService.buildAuthUrl({ state, req, loginHint: email });
    return { url };
  },

  /**
   * Handles Google's redirect. Always resolves to a frontend URL (never throws to the
   * browser) so the user lands back in the app with a readable result.
   */
  async completeGmailConnect({ code, state, error, req }) {
    const payload = verifyState(state);
    if (!payload) {
      return buildReturnUrl(null, "error", { reason: "invalid_state" });
    }
    const origin = payload.origin;

    if (error) {
      return buildReturnUrl(origin, error === "access_denied" ? "cancelled" : "error", {
        reason: error === "access_denied" ? "denied" : "google_error",
      });
    }
    if (!code) {
      return buildReturnUrl(origin, "error", { reason: "missing_code" });
    }

    try {
      ensureConfigured();
      const tokens = await gmailService.exchangeCode({ code: String(code), req });

      if (!tokens.email || !tokens.emailVerified) {
        return buildReturnUrl(origin, "error", { reason: "email_unverified" });
      }
      if (!tokens.scope.split(" ").includes(gmailService.GMAIL_SCOPE)) {
        return buildReturnUrl(origin, "error", { reason: "permission_missing" });
      }
      if (!tokens.refreshToken) {
        return buildReturnUrl(origin, "error", { reason: "no_refresh_token" });
      }

      await emailConnectionRepository.replaceForUser({
        userId: payload.sub,
        provider: PROVIDER_GMAIL,
        accountEmail: tokens.email,
        refreshTokenEnc: tokenCrypto.encrypt(tokens.refreshToken),
        scopes: tokens.scope,
      });

      return buildReturnUrl(origin, "connected");
    } catch (err) {
      console.error("[gmail connect] failed:", err.code || err.message);
      return buildReturnUrl(origin, "error", { reason: err.code === "GMAIL_NOT_CONFIGURED" ? "not_configured" : "failed" });
    }
  },

  async pushGmailSignature({ userId, signatureId, html }) {
    ensureConfigured();

    const signature = await signatureRepository.findByIdForUser(signatureId, userId);
    if (!signature) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }

    const connection = await emailConnectionRepository.findWithTokenByUser(userId, PROVIDER_GMAIL);
    if (!connection) {
      throw new AppError("Connect your Gmail account first.", 409, "GMAIL_NOT_CONNECTED");
    }

    const cleanHtml = gmailService.prepareSignatureHtml(html);

    let accessToken;
    try {
      const refreshToken = tokenCrypto.decrypt(connection.refreshTokenEnc);
      accessToken = await gmailService.refreshAccessToken(refreshToken);
    } catch (err) {
      if (err instanceof gmailService.GmailReconnectRequiredError) {
        await emailConnectionRepository.deleteById(connection.id);
      }
      throw err;
    }

    try {
      await gmailService.pushSignature({
        accessToken,
        sendAsEmail: connection.accountEmail,
        html: cleanHtml,
      });
    } catch (err) {
      if (err instanceof gmailService.GmailReconnectRequiredError) {
        await emailConnectionRepository.deleteById(connection.id);
      }
      throw err;
    }

    const updated = await emailConnectionRepository.markPushed(connection.id, signatureId);
    return {
      accountEmail: connection.accountEmail,
      lastPushedAt: updated?.lastPushedAt ? new Date(updated.lastPushedAt).toISOString() : new Date().toISOString(),
      characters: cleanHtml.length,
    };
  },

  async disconnectGmail(userId) {
    const connection = await emailConnectionRepository.findWithTokenByUser(userId, PROVIDER_GMAIL);
    if (connection) {
      try {
        await gmailService.revokeToken(tokenCrypto.decrypt(connection.refreshTokenEnc));
      } catch (_) {
        // Could not decrypt or revoke: still remove the stored connection below.
      }
    }
    const removed = await emailConnectionRepository.deleteByUser(userId, PROVIDER_GMAIL);
    return { disconnected: removed > 0 };
  },
};

module.exports = integrationService;
