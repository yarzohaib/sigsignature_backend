const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const gmailService = require("./gmail.service");
const zohoService = require("./zoho.service");
const oauthService = require("./oauth.service");
const tokenCrypto = require("../utils/tokenCrypto");
const emailConnectionRepository = require("../repositories/email-connection.repository");
const signatureRepository = require("../repositories/signature.repository");
const { sanitizeFrontendOrigin } = require("../utils/frontendOrigin");
const { AppError, BadRequestError, NotFoundError } = require("../utils/errors");

const PROVIDER_GMAIL = "gmail";
const PROVIDER_ZOHO = "zoho";
const STATE_TTL = "10m";
const RETURN_PATH = "/settings";

function ensureConfigured() {
  if (!gmailService.isConfigured() || !tokenCrypto.isConfigured()) {
    throw new AppError("Gmail integration is not configured on this server.", 503, "GMAIL_NOT_CONFIGURED");
  }
}

function signState({ userId, frontendOrigin, provider = PROVIDER_GMAIL }) {
  return jwt.sign(
    { type: `${provider}_connect`, sub: userId, origin: frontendOrigin, nonce: crypto.randomBytes(12).toString("hex") },
    process.env.JWT_ACCESS_SECRET,
    {
      algorithm: "HS256",
      issuer: process.env.JWT_ISSUER || "sigsignature.com",
      audience: `sigsignature-${provider}-connect`,
      expiresIn: STATE_TTL,
    }
  );
}

function verifyState(state, provider = PROVIDER_GMAIL) {
  try {
    const payload = jwt.verify(String(state || ""), process.env.JWT_ACCESS_SECRET, {
      algorithms: ["HS256"],
      issuer: process.env.JWT_ISSUER || "sigsignature.com",
      audience: `sigsignature-${provider}-connect`,
    });
    if (payload.type !== `${provider}_connect` || !payload.sub) return null;
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

function buildReturnUrl(origin, status, extra = {}, provider = PROVIDER_GMAIL) {
  const base = sanitizeFrontendOrigin(origin) || oauthService.getFrontendUrl();
  const url = new URL(RETURN_PATH, base);
  url.searchParams.set("integration", provider);
  url.searchParams.set("status", status);
  Object.entries(extra).forEach(([key, value]) => url.searchParams.set(key, value));
  return url.toString();
}

const integrationService = {
  PROVIDER_GMAIL,
  PROVIDER_ZOHO,
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
  /* ------------------------------- Zoho ------------------------------- */

  async getZohoStatus(userId) {
    const connection = (await emailConnectionRepository.findByUser(userId, PROVIDER_ZOHO))[0] || null;
    return {
      configured: zohoService.isConfigured() && tokenCrypto.isConfigured(),
      connected: Boolean(connection),
      connection: formatConnection(connection),
    };
  },

  async startZohoConnect({ userId, email, frontendOrigin, req }) {
    if (!zohoService.isConfigured() || !tokenCrypto.isConfigured()) {
      throw new AppError("Zoho integration is not configured on this server.", 503, "ZOHO_NOT_CONFIGURED");
    }
    const origin = sanitizeFrontendOrigin(frontendOrigin) || sanitizeFrontendOrigin(req?.headers?.origin);
    if (!origin) {
      throw new BadRequestError("Could not tell which site to return to after connecting Zoho Mail.", "ZOHO_BAD_ORIGIN");
    }
    const state = signState({ userId, frontendOrigin: origin, provider: PROVIDER_ZOHO });
    return { url: zohoService.buildAuthUrl({ state, req, loginHint: email }) };
  },

  async completeZohoConnect({ code, state, error, accountsServer, location, req }) {
    const payload = verifyState(state, PROVIDER_ZOHO);
    if (!payload) {
      return buildReturnUrl(null, "error", { reason: "invalid_state" }, PROVIDER_ZOHO);
    }
    const origin = payload.origin;

    if (error) {
      const denied = error === "access_denied";
      return buildReturnUrl(origin, denied ? "cancelled" : "error", { reason: denied ? "denied" : "zoho_error" }, PROVIDER_ZOHO);
    }
    if (!code) {
      return buildReturnUrl(origin, "error", { reason: "missing_code" }, PROVIDER_ZOHO);
    }

    try {
      if (!zohoService.isConfigured() || !tokenCrypto.isConfigured()) {
        return buildReturnUrl(origin, "error", { reason: "not_configured" }, PROVIDER_ZOHO);
      }
      const tokens = await zohoService.exchangeCode({ code: String(code), accountsServer, location, req });
      if (!tokens.refreshToken) {
        return buildReturnUrl(origin, "error", { reason: "no_refresh_token" }, PROVIDER_ZOHO);
      }
      const accountEmail = await zohoService.getPrimaryAddress(tokens.dc, tokens.accessToken);

      await emailConnectionRepository.replaceForUser({
        userId: payload.sub,
        provider: PROVIDER_ZOHO,
        accountEmail,
        refreshTokenEnc: tokenCrypto.encrypt(tokens.refreshToken),
        scopes: zohoService.SCOPES.join(","),
        metadata: JSON.stringify({ dc: tokens.dc }),
      });
      return buildReturnUrl(origin, "connected", {}, PROVIDER_ZOHO);
    } catch (err) {
      console.error("[zoho connect] failed:", err.code || err.message);
      return buildReturnUrl(origin, "error", { reason: err.code === "ZOHO_NO_MAILBOX" ? "no_mailbox" : "failed" }, PROVIDER_ZOHO);
    }
  },

  async pushZohoSignature({ userId, signatureId, html }) {
    if (!zohoService.isConfigured() || !tokenCrypto.isConfigured()) {
      throw new AppError("Zoho integration is not configured on this server.", 503, "ZOHO_NOT_CONFIGURED");
    }
    const signature = await signatureRepository.findByIdForUser(signatureId, userId);
    if (!signature) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }
    const connection = await emailConnectionRepository.findWithTokenByUser(userId, PROVIDER_ZOHO);
    if (!connection) {
      throw new AppError("Connect your Zoho Mail account first.", 409, "ZOHO_NOT_CONNECTED");
    }

    const cleanHtml = gmailService.prepareSignatureHtml(html, { maxLength: zohoService.MAX_ZOHO_SIGNATURE_LENGTH });

    let meta = {};
    try {
      meta = JSON.parse(connection.metadata || "{}") || {};
    } catch (_) {
      meta = {};
    }
    const dc = zohoService.isValidDataCenter(meta.dc) ? meta.dc : "com";

    try {
      const refreshToken = tokenCrypto.decrypt(connection.refreshTokenEnc);
      const accessToken = await zohoService.refreshAccessToken(dc, refreshToken);
      const zohoSignatureId = await zohoService.upsertSignature({
        dc,
        accessToken,
        accountEmail: connection.accountEmail,
        html: cleanHtml,
        knownSignatureId: meta.signatureId,
      });
      if (zohoSignatureId && zohoSignatureId !== meta.signatureId) {
        await emailConnectionRepository.saveMetadata(connection.id, JSON.stringify({ dc, signatureId: zohoSignatureId }));
      }
    } catch (err) {
      if (err instanceof zohoService.ZohoReconnectRequiredError) {
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

  async disconnectZoho(userId) {
    const connection = await emailConnectionRepository.findWithTokenByUser(userId, PROVIDER_ZOHO);
    if (connection) {
      try {
        const meta = JSON.parse(connection.metadata || "{}") || {};
        const dc = zohoService.isValidDataCenter(meta.dc) ? meta.dc : "com";
        await zohoService.revokeToken(dc, tokenCrypto.decrypt(connection.refreshTokenEnc));
      } catch (_) {
        // Could not decrypt or revoke: still remove the stored connection below.
      }
    }
    const removed = await emailConnectionRepository.deleteByUser(userId, PROVIDER_ZOHO);
    return { disconnected: removed > 0 };
  },
};

module.exports = integrationService;
