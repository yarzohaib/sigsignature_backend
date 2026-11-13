const sanitizeHtml = require("sanitize-html");
const oauthService = require("./oauth.service");
const {
  AppError,
  BadRequestError,
  BadGatewayError,
  NotFoundError,
  TooManyRequestsError,
} = require("../utils/errors");

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1";

const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic";
const SCOPES = ["openid", "email", GMAIL_SCOPE];

/** Gmail rejects signatures longer than this many characters. */
const MAX_GMAIL_SIGNATURE_LENGTH = 10000;

const CALLBACK_PATH = "/api/v1/integrations/gmail/callback";

class GmailReconnectRequiredError extends AppError {
  constructor(message = "Gmail access was removed or expired. Please reconnect your Gmail account.") {
    super(message, 409, "GMAIL_RECONNECT_REQUIRED");
  }
}

function getClientCredentials() {
  const clientId = (process.env.GOOGLE_CLIENT_ID || "").trim();
  const clientSecret = (process.env.GOOGLE_CLIENT_SECRET || "").trim();
  if (!clientId || !clientSecret) {
    throw new AppError("Gmail integration is not configured on this server.", 503, "GMAIL_NOT_CONFIGURED");
  }
  return { clientId, clientSecret };
}

function isConfigured() {
  return Boolean(
    (process.env.GOOGLE_CLIENT_ID || "").trim() && (process.env.GOOGLE_CLIENT_SECRET || "").trim()
  );
}

function getRedirectUri(req) {
  return `${oauthService.getBackendUrl(req)}${CALLBACK_PATH}`;
}

function buildAuthUrl({ state, req, loginHint }) {
  const { clientId } = getClientCredentials();
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: getRedirectUri(req),
    response_type: "code",
    scope: SCOPES.join(" "),
    state,
    // offline + consent makes Google return a refresh token every time
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "false",
  });
  if (loginHint) {
    params.set("login_hint", loginHint);
  }
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

function decodeIdTokenPayload(idToken) {
  // The id_token is received directly from Google over TLS in the token response,
  // so reading its payload without verifying the signature is acceptable here.
  try {
    const payload = String(idToken || "").split(".")[1];
    if (!payload) return null;
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch (_) {
    return null;
  }
}

async function postForm(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
  let json = null;
  try {
    json = await response.json();
  } catch (_) {
    json = null;
  }
  return { ok: response.ok, status: response.status, json };
}

async function exchangeCode({ code, req }) {
  const { clientId, clientSecret } = getClientCredentials();
  const result = await postForm(GOOGLE_TOKEN_URL, {
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: getRedirectUri(req),
    grant_type: "authorization_code",
  });

  if (!result.ok || !result.json?.access_token) {
    throw new BadRequestError("Google did not accept the sign in. Please try again.", "GMAIL_CODE_REJECTED");
  }

  const claims = decodeIdTokenPayload(result.json.id_token);
  return {
    accessToken: result.json.access_token,
    refreshToken: result.json.refresh_token || null,
    scope: String(result.json.scope || ""),
    email: claims?.email ? String(claims.email).toLowerCase() : null,
    emailVerified: claims?.email_verified !== false,
  };
}

async function refreshAccessToken(refreshToken) {
  const { clientId, clientSecret } = getClientCredentials();
  const result = await postForm(GOOGLE_TOKEN_URL, {
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "refresh_token",
  });

  if (!result.ok || !result.json?.access_token) {
    if (result.json?.error === "invalid_grant" || result.status === 400 || result.status === 401) {
      throw new GmailReconnectRequiredError();
    }
    throw new BadGatewayError("Could not reach Google right now. Please try again.", "GMAIL_UNAVAILABLE");
  }
  return result.json.access_token;
}

async function revokeToken(token) {
  try {
    await postForm(GOOGLE_REVOKE_URL, { token });
  } catch (_) {
    // Best effort: the local connection is removed either way.
  }
}

/**
 * Checks the HTML for things Gmail cannot keep, then strips anything unsafe.
 * Throws a readable BadRequestError when the signature cannot be used in Gmail.
 */
function prepareSignatureHtml(rawHtml) {
  const html = String(rawHtml || "");

  if (/<img\b[^>]*\bsrc\s*=\s*["']?\s*data:/i.test(html)) {
    throw new BadRequestError(
      "This signature contains an embedded image. Upload the image so it has a public link, then try again.",
      "GMAIL_EMBEDDED_IMAGE"
    );
  }

  const clean = sanitizeHtml(html, {
    allowedTags: [
      "a", "abbr", "b", "blockquote", "br", "center", "div", "em", "font", "h1", "h2", "h3", "h4",
      "h5", "h6", "hr", "i", "img", "li", "ol", "p", "small", "span", "strong", "sub", "sup",
      "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul",
    ],
    allowedAttributes: {
      a: ["href", "target", "rel", "title", "style"],
      img: ["src", "alt", "width", "height", "style", "border", "title"],
      font: ["color", "face", "size", "style"],
      "*": [
        "style", "align", "valign", "width", "height", "bgcolor",
        "cellpadding", "cellspacing", "border", "colspan", "rowspan",
      ],
    },
    allowedSchemes: ["http", "https", "mailto", "tel"],
    allowedSchemesByTag: { img: ["https"] },
    allowProtocolRelative: false,
    transformTags: {
      a: (tagName, attribs) => ({
        tagName,
        attribs: { ...attribs, rel: "noopener noreferrer" },
      }),
    },
  }).trim();

  if (!clean) {
    throw new BadRequestError("The signature is empty after cleaning. Please check it and try again.", "GMAIL_EMPTY_SIGNATURE");
  }

  if (clean.length > MAX_GMAIL_SIGNATURE_LENGTH) {
    throw new BadRequestError(
      `This signature is too large for Gmail (${clean.length} of ${MAX_GMAIL_SIGNATURE_LENGTH} characters). Try removing an element or shortening the text.`,
      "GMAIL_SIGNATURE_TOO_LARGE"
    );
  }

  return clean;
}

async function pushSignature({ accessToken, sendAsEmail, html }) {
  const url = `${GMAIL_API_BASE}/users/me/settings/sendAs/${encodeURIComponent(sendAsEmail)}`;
  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ signature: html }),
  });

  if (response.ok) {
    return true;
  }

  if (response.status === 401) {
    throw new GmailReconnectRequiredError();
  }
  if (response.status === 403) {
    throw new GmailReconnectRequiredError(
      "Gmail did not allow Sig Signature to change your signature. Please reconnect and approve the permission."
    );
  }
  if (response.status === 404) {
    throw new NotFoundError("That Gmail address was not found on your account.", "GMAIL_ADDRESS_NOT_FOUND");
  }
  if (response.status === 429) {
    throw new TooManyRequestsError("Gmail is limiting requests right now. Please try again in a few minutes.", "GMAIL_RATE_LIMITED");
  }
  if (response.status === 400) {
    throw new BadRequestError("Gmail rejected this signature. Please check it and try again.", "GMAIL_REJECTED_SIGNATURE");
  }
  throw new BadGatewayError("Gmail is not responding right now. Please try again.", "GMAIL_UNAVAILABLE");
}

module.exports = {
  GMAIL_SCOPE,
  SCOPES,
  MAX_GMAIL_SIGNATURE_LENGTH,
  CALLBACK_PATH,
  GmailReconnectRequiredError,
  isConfigured,
  getRedirectUri,
  buildAuthUrl,
  exchangeCode,
  refreshAccessToken,
  revokeToken,
  prepareSignatureHtml,
  pushSignature,
};
