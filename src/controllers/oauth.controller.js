const crypto = require("crypto");
const oauthService = require("../services/oauth.service");
const { setAuthCookies } = require("../utils/cookies");
const { UnauthorizedError } = require("../utils/errors");

const OAUTH_COOKIE_NAME = "oauth_state";
const OAUTH_ORIGIN_COOKIE_NAME = "oauth_frontend_origin";
const OAUTH_REF_COOKIE_NAME = "oauth_referral_code";

function getCookieBaseOptions(req) {
  const isHttps =
    process.env.NODE_ENV === "production" ||
    Boolean(req?.secure) ||
    req?.protocol === "https" ||
    req?.headers?.["x-forwarded-proto"] === "https";

  return {
    httpOnly: true,
    sameSite: "lax",
    secure: Boolean(isHttps),
    path: "/api/v1/auth",
  };
}

function sanitizeFrontendOrigin(originCandidate) {
  if (!originCandidate || typeof originCandidate !== "string") {
    return null;
  }
  try {
    const parsed = new URL(originCandidate);
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1") {
      return parsed.origin;
    }
    if (
      host === "sigsignature.com" ||
      host === "www.sigsignature.com" ||
      host.endsWith(".sigsignature.com") ||
      host.endsWith(".vercel.app")
    ) {
      return parsed.origin;
    }
  } catch (_) {}
  return null;
}

const oauthController = {
  googleAuth(req, res) {
    const state = crypto.randomBytes(32).toString("hex");
    const cookieOptions = {
      ...getCookieBaseOptions(req),
      maxAge: 10 * 60 * 1000, // 10 minutes
    };

    res.cookie(OAUTH_COOKIE_NAME, state, cookieOptions);

    const frontendOrigin = sanitizeFrontendOrigin(req.query.frontend_url);
    if (frontendOrigin) {
      res.cookie(OAUTH_ORIGIN_COOKIE_NAME, frontendOrigin, cookieOptions);
    }

    const referralCode = req.query.ref || req.query.referral_code;
    if (referralCode && typeof referralCode === "string") {
      res.cookie(OAUTH_REF_COOKIE_NAME, referralCode.trim().toUpperCase(), cookieOptions);
    }

    const targetUrl = oauthService.getGoogleAuthUrl(state, req);
    return res.redirect(302, targetUrl);
  },

  githubAuth(req, res) {
    const state = crypto.randomBytes(32).toString("hex");
    const cookieOptions = {
      ...getCookieBaseOptions(req),
      maxAge: 10 * 60 * 1000, // 10 minutes
    };

    res.cookie(OAUTH_COOKIE_NAME, state, cookieOptions);

    const frontendOrigin = sanitizeFrontendOrigin(req.query.frontend_url);
    if (frontendOrigin) {
      res.cookie(OAUTH_ORIGIN_COOKIE_NAME, frontendOrigin, cookieOptions);
    }

    const referralCode = req.query.ref || req.query.referral_code;
    if (referralCode && typeof referralCode === "string") {
      res.cookie(OAUTH_REF_COOKIE_NAME, referralCode.trim().toUpperCase(), cookieOptions);
    }

    const targetUrl = oauthService.getGithubAuthUrl(state, req);
    return res.redirect(302, targetUrl);
  },

  async googleCallback(req, res) {
    const cookieOptions = getCookieBaseOptions(req);
    const savedFrontendOrigin = req.cookies ? req.cookies[OAUTH_ORIGIN_COOKIE_NAME] : undefined;
    const frontendBase = sanitizeFrontendOrigin(savedFrontendOrigin) || oauthService.getFrontendUrl(req);
    const { code, state, error } = req.query;
    const savedState = req.cookies ? req.cookies[OAUTH_COOKIE_NAME] : undefined;

    // Always clear the state, origin, and referral cookies
    const savedRefCode = req.cookies ? req.cookies[OAUTH_REF_COOKIE_NAME] : undefined;
    res.clearCookie(OAUTH_COOKIE_NAME, cookieOptions);
    res.clearCookie(OAUTH_ORIGIN_COOKIE_NAME, cookieOptions);
    res.clearCookie(OAUTH_REF_COOKIE_NAME, cookieOptions);

    if (error) {
      console.error("Google returned OAuth error query:", error);
      const codeType = error === "access_denied" ? "oauth_cancelled" : "oauth_failed";
      return res.redirect(302, `${frontendBase}/login?error=${codeType}`);
    }

    if (!state || !savedState || !oauthService.safeCompareState(state, savedState)) {
      console.error("State mismatch or missing in Google callback:", { stateReceived: !!state, stateSaved: !!savedState });
      return res.redirect(302, `${frontendBase}/login?error=oauth_failed`);
    }

    if (!code) {
      console.error("Authorization code missing in Google callback");
      return res.redirect(302, `${frontendBase}/login?error=oauth_failed`);
    }

    try {
      const user = await oauthService.handleGoogleCallback(code, req, savedRefCode);
      const loginCode = await oauthService.createLoginCodeForUser(user.id);

      return res.redirect(302, `${frontendBase}/auth/callback?code=${loginCode}`);
    } catch (err) {
      console.error("Google callback processing error:", err);
      let errorParam = "oauth_failed";
      if (err.message === "email_not_verified") {
        errorParam = "email_not_verified";
      } else if (err.message === "account_inactive") {
        errorParam = "account_inactive";
      } else if (err.message === "oauth_cancelled") {
        errorParam = "oauth_cancelled";
      }

      return res.redirect(302, `${frontendBase}/login?error=${errorParam}`);
    }
  },

  async githubCallback(req, res) {
    const cookieOptions = getCookieBaseOptions(req);
    const savedFrontendOrigin = req.cookies ? req.cookies[OAUTH_ORIGIN_COOKIE_NAME] : undefined;
    const frontendBase = sanitizeFrontendOrigin(savedFrontendOrigin) || oauthService.getFrontendUrl(req);
    const { code, state, error } = req.query;
    const savedState = req.cookies ? req.cookies[OAUTH_COOKIE_NAME] : undefined;

    // Always clear the state, origin, and referral cookies
    const savedRefCode = req.cookies ? req.cookies[OAUTH_REF_COOKIE_NAME] : undefined;
    res.clearCookie(OAUTH_COOKIE_NAME, cookieOptions);
    res.clearCookie(OAUTH_ORIGIN_COOKIE_NAME, cookieOptions);
    res.clearCookie(OAUTH_REF_COOKIE_NAME, cookieOptions);

    if (error) {
      console.error("GitHub returned OAuth error query:", error);
      const codeType = error === "access_denied" ? "oauth_cancelled" : "oauth_failed";
      return res.redirect(302, `${frontendBase}/login?error=${codeType}`);
    }

    if (!state || !savedState || !oauthService.safeCompareState(state, savedState)) {
      console.error("State mismatch or missing in GitHub callback:", { stateReceived: !!state, stateSaved: !!savedState });
      return res.redirect(302, `${frontendBase}/login?error=oauth_failed`);
    }

    if (!code) {
      console.error("Authorization code missing in GitHub callback");
      return res.redirect(302, `${frontendBase}/login?error=oauth_failed`);
    }

    try {
      const user = await oauthService.handleGithubCallback(code, req, savedRefCode);
      const loginCode = await oauthService.createLoginCodeForUser(user.id);

      return res.redirect(302, `${frontendBase}/auth/callback?code=${loginCode}`);
    } catch (err) {
      console.error("GitHub callback processing error:", err);
      let errorParam = "oauth_failed";
      if (err.message === "email_not_verified") {
        errorParam = "email_not_verified";
      } else if (err.message === "account_inactive") {
        errorParam = "account_inactive";
      } else if (err.message === "oauth_cancelled") {
        errorParam = "oauth_cancelled";
      }

      return res.redirect(302, `${frontendBase}/login?error=${errorParam}`);
    }
  },

  async oauthExchange(req, res, next) {
    try {
      const { code } = req.body;
      const result = await oauthService.exchangeLoginCode(code, {
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
      });

      if (result.tokens) {
        setAuthCookies(res, result.tokens);
      }

      return res.status(200).json({
        success: true,
        message: "Login successful",
        data: result,
      });
    } catch (error) {
      if (error.statusCode === 401 || error.message === "Invalid or expired code") {
        return next(new UnauthorizedError("Invalid or expired code"));
      }
      next(error);
    }
  },
};

module.exports = oauthController;
