const oauthService = require("./oauth.service");
const {
  AppError,
  BadRequestError,
  BadGatewayError,
  TooManyRequestsError,
} = require("../utils/errors");

/**
 * Zoho runs separate data centers. A user's account lives in one of them, and tokens and APIs
 * must be called on that data center. Only these exact hosts are ever contacted.
 */
const DATA_CENTERS = {
  com: { accounts: "https://accounts.zoho.com", mail: "https://mail.zoho.com" },
  eu: { accounts: "https://accounts.zoho.eu", mail: "https://mail.zoho.eu" },
  in: { accounts: "https://accounts.zoho.in", mail: "https://mail.zoho.in" },
  "com.au": { accounts: "https://accounts.zoho.com.au", mail: "https://mail.zoho.com.au" },
  jp: { accounts: "https://accounts.zoho.jp", mail: "https://mail.zoho.jp" },
  "com.cn": { accounts: "https://accounts.zoho.com.cn", mail: "https://mail.zoho.com.cn" },
  sa: { accounts: "https://accounts.zoho.sa", mail: "https://mail.zoho.sa" },
  ae: { accounts: "https://accounts.zoho.ae", mail: "https://mail.zoho.ae" },
  ca: { accounts: "https://accounts.zohocloud.ca", mail: "https://mail.zohocloud.ca" },
};

// Zoho's `location` values that differ from the keys above
const LOCATION_ALIASES = { us: "com", au: "com.au", cn: "com.cn" };

const SCOPES = ["ZohoMail.accounts.READ", "ZohoMail.accounts.CREATE", "ZohoMail.accounts.UPDATE"];
const CALLBACK_PATH = "/api/v1/integrations/zoho/callback";
const SIGNATURE_NAME = "Sig Signature";
const SIGNATURE_POSITION = 0; // 0 = below the quoted text in replies, 1 = above
const MAX_ZOHO_SIGNATURE_LENGTH = 30000;

class ZohoReconnectRequiredError extends AppError {
  constructor(message = "Zoho access expired or was removed. Please reconnect Zoho Mail.") {
    super(message, 409, "ZOHO_RECONNECT_REQUIRED");
  }
}

function getCredentials() {
  return { clientId: process.env.ZOHO_CLIENT_ID, clientSecret: process.env.ZOHO_CLIENT_SECRET };
}

function isConfigured() {
  const { clientId, clientSecret } = getCredentials();
  return Boolean(clientId && clientSecret);
}

function getRedirectUri(req) {
  return `${oauthService.getBackendUrl(req)}${CALLBACK_PATH}`;
}

function isValidDataCenter(dc) {
  return typeof dc === "string" && Object.prototype.hasOwnProperty.call(DATA_CENTERS, dc);
}

/** Works out the data center from Zoho's callback values, trusting only known hosts. */
function resolveDataCenter({ accountsServer, location } = {}) {
  if (accountsServer) {
    const normalized = String(accountsServer).replace(/\/+$/, "").toLowerCase();
    const match = Object.keys(DATA_CENTERS).find((key) => DATA_CENTERS[key].accounts === normalized);
    if (match) return match;
  }
  if (location) {
    const key = String(location).toLowerCase();
    const mapped = LOCATION_ALIASES[key] || key;
    if (isValidDataCenter(mapped)) return mapped;
  }
  return "com";
}

function buildAuthUrl({ state, req, loginHint }) {
  const { clientId } = getCredentials();
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: getRedirectUri(req),
    scope: SCOPES.join(","),
    access_type: "offline",
    prompt: "consent",
    state,
  });
  if (loginHint) params.set("login_hint", loginHint);
  return `${DATA_CENTERS.com.accounts}/oauth/v2/auth?${params.toString()}`;
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

async function zohoApi(dc, accessToken, path, { method = "GET", body } = {}) {
  const response = await fetch(`${DATA_CENTERS[dc].mail}${path}`, {
    method,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Zoho-oauthtoken ${accessToken}`,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await response.json();
  } catch (_) {
    json = null;
  }
  return { ok: response.ok, status: response.status, json };
}

function mapApiError(result) {
  if (result.status === 401 || result.status === 403) {
    return new ZohoReconnectRequiredError();
  }
  if (result.status === 429) {
    return new TooManyRequestsError("Zoho is limiting requests right now. Please try again in a few minutes.", "ZOHO_RATE_LIMITED");
  }
  if (result.status === 400) {
    return new BadRequestError("Zoho rejected this signature. Please check it and try again.", "ZOHO_REJECTED_SIGNATURE");
  }
  return new BadGatewayError("Zoho Mail is not responding right now. Please try again.", "ZOHO_UNAVAILABLE");
}

async function exchangeCode({ code, accountsServer, location, req }) {
  const { clientId, clientSecret } = getCredentials();
  const dc = resolveDataCenter({ accountsServer, location });
  const result = await postForm(`${DATA_CENTERS[dc].accounts}/oauth/v2/token`, {
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: getRedirectUri(req),
  });
  // Zoho can answer HTTP 200 with an error field
  if (!result.ok || !result.json?.access_token || result.json?.error) {
    throw new BadRequestError("Zoho did not accept the sign in. Please try again.", "ZOHO_CODE_REJECTED");
  }
  return {
    dc,
    accessToken: result.json.access_token,
    refreshToken: result.json.refresh_token || null,
  };
}

async function refreshAccessToken(dc, refreshToken) {
  const { clientId, clientSecret } = getCredentials();
  const result = await postForm(`${DATA_CENTERS[dc].accounts}/oauth/v2/token`, {
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  if (!result.ok || !result.json?.access_token || result.json?.error) {
    const error = result.json?.error;
    if (error === "invalid_code" || error === "invalid_client" || result.status === 400 || result.status === 401) {
      throw new ZohoReconnectRequiredError();
    }
    throw new BadGatewayError("Could not reach Zoho right now. Please try again.", "ZOHO_UNAVAILABLE");
  }
  return result.json.access_token;
}

async function revokeToken(dc, refreshToken) {
  try {
    await postForm(`${DATA_CENTERS[dc].accounts}/oauth/v2/token/revoke`, { token: refreshToken });
  } catch (_) {
    // Best effort: the local connection is removed either way.
  }
}

/** The mailbox the signature is for. Uses the first account's primary address. */
async function getPrimaryAddress(dc, accessToken) {
  const result = await zohoApi(dc, accessToken, "/api/accounts");
  if (!result.ok) throw mapApiError(result);
  const accounts = Array.isArray(result.json?.data) ? result.json.data : [];
  const account = accounts.find((a) => a && a.primaryEmailAddress) || null;
  if (!account) {
    throw new BadRequestError("No Zoho Mail mailbox was found on this account.", "ZOHO_NO_MAILBOX");
  }
  return String(account.primaryEmailAddress).toLowerCase();
}

/**
 * Creates the "Sig Signature" signature in Zoho Mail, or updates it when it already exists,
 * and assigns it to the user's primary address. Returns the Zoho signature id.
 */
async function upsertSignature({ dc, accessToken, accountEmail, html, knownSignatureId }) {
  const list = await zohoApi(dc, accessToken, "/api/accounts/signature");
  if (!list.ok) throw mapApiError(list);

  const existing = (Array.isArray(list.json?.data) ? list.json.data : []).find(
    (s) => s && ((knownSignatureId && String(s.id) === String(knownSignatureId)) || s.name === SIGNATURE_NAME)
  );

  const payload = {
    name: SIGNATURE_NAME,
    content: html,
    position: SIGNATURE_POSITION,
    assignUsers: accountEmail,
  };

  const result = existing
    ? await zohoApi(dc, accessToken, "/api/accounts/signature", { method: "PUT", body: { ...payload, id: String(existing.id) } })
    : await zohoApi(dc, accessToken, "/api/accounts/signature", { method: "POST", body: payload });

  if (!result.ok) throw mapApiError(result);
  return String(result.json?.data?.id || existing?.id || "");
}

module.exports = {
  DATA_CENTERS,
  SCOPES,
  CALLBACK_PATH,
  SIGNATURE_NAME,
  MAX_ZOHO_SIGNATURE_LENGTH,
  ZohoReconnectRequiredError,
  isConfigured,
  isValidDataCenter,
  resolveDataCenter,
  getRedirectUri,
  buildAuthUrl,
  exchangeCode,
  refreshAccessToken,
  revokeToken,
  getPrimaryAddress,
  upsertSignature,
};
