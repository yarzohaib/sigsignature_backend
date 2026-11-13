const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

process.env.NODE_ENV = "test";
process.env.RESEND_API_KEY = process.env.RESEND_API_KEY || "re_test_key";
process.env.JWT_ACCESS_SECRET = "test-access-secret-1234567890";
process.env.GOOGLE_CLIENT_ID = "client-id.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "client-secret";
process.env.INTEGRATION_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
process.env.BACKEND_URL = "https://api.example.test";
process.env.FRONTEND_URL = "https://www.sigsignature.com";

// In memory stand ins for the two repositories, installed before the service loads
const connections = [];
const signatures = new Map();

const emailRepoMock = {
  async findByUser(userId, provider) {
    return connections.filter((c) => c.userId === userId && c.provider === provider);
  },
  async findWithTokenByUser(userId, provider) {
    return connections.find((c) => c.userId === userId && c.provider === provider) || null;
  },
  async replaceForUser({ userId, provider, accountEmail, refreshTokenEnc, scopes }) {
    for (let i = connections.length - 1; i >= 0; i -= 1) {
      if (connections[i].userId === userId && connections[i].provider === provider) connections.splice(i, 1);
    }
    const row = { id: `c${connections.length + 1}`, userId, provider, accountEmail, refreshTokenEnc, scopes, createdAt: new Date() };
    connections.push(row);
    return row;
  },
  async markPushed(id, signatureId) {
    const row = connections.find((c) => c.id === id);
    if (row) {
      row.lastPushedAt = new Date();
      row.lastSignatureId = signatureId;
    }
    return row || null;
  },
  async deleteById(id) {
    const i = connections.findIndex((c) => c.id === id);
    if (i >= 0) connections.splice(i, 1);
  },
  async deleteByUser(userId, provider) {
    let count = 0;
    for (let i = connections.length - 1; i >= 0; i -= 1) {
      if (connections[i].userId === userId && connections[i].provider === provider) {
        connections.splice(i, 1);
        count += 1;
      }
    }
    return count;
  },
};

const signatureRepoMock = {
  async findByIdForUser(id, userId) {
    const s = signatures.get(id);
    return s && s.userId === userId ? s : null;
  },
};

function installMock(relativePath, exportsObject) {
  const resolved = require.resolve(relativePath);
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsObject };
}
installMock("../src/repositories/email-connection.repository", emailRepoMock);
installMock("../src/repositories/signature.repository", signatureRepoMock);

const tokenCrypto = require("../src/utils/tokenCrypto");
const gmailService = require("../src/services/gmail.service");
const integrationService = require("../src/services/integration.service");
const { sanitizeFrontendOrigin } = require("../src/utils/frontendOrigin");

const USER_ID = "11111111-1111-4111-8111-111111111111";
const SIGNATURE_ID = "22222222-2222-4222-8222-222222222222";
const GOOD_HTML =
  '<table cellpadding="0" cellspacing="0"><tr><td style="font-family:Arial;font-size:14px"><b>Ada Lovelace</b><br/>Engineer <a href="https://example.com">site</a></td><td><img src="https://cdn.example.com/logo.png" width="60" alt="logo"/></td></tr></table>';

function idToken(claims) {
  return `x.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.y`;
}

const realFetch = global.fetch;
let fetchCalls;

function mockFetch(handler) {
  fetchCalls = [];
  global.fetch = async (url, init = {}) => {
    fetchCalls.push({ url: String(url), init });
    return handler(String(url), init);
  };
}

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

beforeEach(() => {
  connections.length = 0;
  signatures.clear();
  signatures.set(SIGNATURE_ID, { id: SIGNATURE_ID, userId: USER_ID });
});

afterEach(() => {
  global.fetch = realFetch;
});

describe("tokenCrypto", () => {
  test("round trips a token and never stores it in plain text", () => {
    const encrypted = tokenCrypto.encrypt("1//refresh-token-value");
    assert.ok(encrypted.startsWith("v1."));
    assert.ok(!encrypted.includes("refresh-token-value"));
    assert.equal(tokenCrypto.decrypt(encrypted), "1//refresh-token-value");
  });

  test("produces a different ciphertext every time", () => {
    assert.notEqual(tokenCrypto.encrypt("same"), tokenCrypto.encrypt("same"));
  });

  test("rejects tampered data", () => {
    const parts = tokenCrypto.encrypt("secret").split(".");
    parts[3] = Buffer.from("tampered!!").toString("base64url");
    assert.throws(() => tokenCrypto.decrypt(parts.join(".")));
  });

  test("reports when the key is missing or the wrong size", () => {
    const original = process.env.INTEGRATION_ENCRYPTION_KEY;
    process.env.INTEGRATION_ENCRYPTION_KEY = "too-short";
    assert.equal(tokenCrypto.isConfigured(), false);
    assert.throws(() => tokenCrypto.encrypt("x"));
    process.env.INTEGRATION_ENCRYPTION_KEY = original;
    assert.equal(tokenCrypto.isConfigured(), true);
  });
});

describe("frontend origin allowlist", () => {
  test("accepts our own sites and rejects others", () => {
    assert.equal(sanitizeFrontendOrigin("https://www.sigsignature.com/path"), "https://www.sigsignature.com");
    assert.equal(sanitizeFrontendOrigin("https://staging.sigsignature.com"), "https://staging.sigsignature.com");
    assert.equal(sanitizeFrontendOrigin("http://localhost:3000"), "http://localhost:3000");
    assert.equal(sanitizeFrontendOrigin("https://evil.example.com"), null);
    assert.equal(sanitizeFrontendOrigin("https://sigsignature.com.evil.com"), null);
    assert.equal(sanitizeFrontendOrigin("http://www.sigsignature.com"), null);
    assert.equal(sanitizeFrontendOrigin("not a url"), null);
  });
});

describe("signed state", () => {
  test("verifies a state we issued", () => {
    const state = integrationService.signState({ userId: USER_ID, frontendOrigin: "https://www.sigsignature.com" });
    const payload = integrationService.verifyState(state);
    assert.equal(payload.sub, USER_ID);
    assert.equal(payload.origin, "https://www.sigsignature.com");
  });

  test("rejects an access token, an expired state and garbage", () => {
    const accessToken = jwt.sign({ sub: USER_ID, type: "access" }, process.env.JWT_ACCESS_SECRET, {
      issuer: "sigsignature.com",
      audience: "sigsignature-app",
    });
    assert.equal(integrationService.verifyState(accessToken), null);

    const expired = jwt.sign({ type: "gmail_connect", sub: USER_ID }, process.env.JWT_ACCESS_SECRET, {
      issuer: "sigsignature.com",
      audience: "sigsignature-gmail-connect",
      expiresIn: -10,
    });
    assert.equal(integrationService.verifyState(expired), null);
    assert.equal(integrationService.verifyState("nope"), null);
  });
});

describe("gmail auth url", () => {
  test("asks for offline access, consent and only the signature settings scope", () => {
    const req = { headers: {}, protocol: "https", get: () => "api.example.test" };
    const url = new URL(gmailService.buildAuthUrl({ state: "abc", req, loginHint: "me@gmail.com" }));
    assert.equal(url.origin + url.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
    assert.equal(url.searchParams.get("access_type"), "offline");
    assert.equal(url.searchParams.get("prompt"), "consent");
    assert.equal(url.searchParams.get("redirect_uri"), "https://api.example.test/api/v1/integrations/gmail/callback");
    assert.equal(url.searchParams.get("scope"), "openid email https://www.googleapis.com/auth/gmail.settings.basic");
    assert.equal(url.searchParams.get("state"), "abc");
    assert.equal(url.searchParams.get("login_hint"), "me@gmail.com");
  });
});

describe("signature html preparation", () => {
  test("keeps tables, links and https images", () => {
    const html = gmailService.prepareSignatureHtml(GOOD_HTML);
    assert.match(html, /<table/);
    assert.match(html, /href="https:\/\/example\.com"/);
    assert.match(html, /src="https:\/\/cdn\.example\.com\/logo\.png"/);
    assert.match(html, /rel="noopener noreferrer"/);
  });

  test("removes scripts, event handlers and javascript links", () => {
    const html = gmailService.prepareSignatureHtml(
      '<div onclick="steal()">Hi<script>alert(1)</script><a href="javascript:alert(1)">x</a><img src="https://a.test/i.png" onerror="alert(1)"/></div>'
    );
    assert.ok(!/script/i.test(html));
    assert.ok(!/onclick|onerror/i.test(html));
    assert.ok(!/javascript:/i.test(html));
  });

  test("rejects embedded base64 images with a clear message", () => {
    assert.throws(
      () => gmailService.prepareSignatureHtml('<img src="data:image/png;base64,AAAA"/>'),
      (error) => error.code === "GMAIL_EMBEDDED_IMAGE" && error.statusCode === 400
    );
  });

  test("rejects signatures over the Gmail size limit", () => {
    const big = `<p>${"a".repeat(gmailService.MAX_GMAIL_SIGNATURE_LENGTH + 10)}</p>`;
    assert.throws(
      () => gmailService.prepareSignatureHtml(big),
      (error) => error.code === "GMAIL_SIGNATURE_TOO_LARGE"
    );
  });
});

describe("connect callback", () => {
  const req = { headers: {}, protocol: "https", get: () => "api.example.test" };
  const goodState = () => integrationService.signState({ userId: USER_ID, frontendOrigin: "https://www.sigsignature.com" });

  test("stores an encrypted refresh token and returns to settings as connected", async () => {
    mockFetch(async () =>
      jsonResponse(200, {
        access_token: "ya29.access",
        refresh_token: "1//refresh",
        scope: "openid email https://www.googleapis.com/auth/gmail.settings.basic",
        id_token: idToken({ email: "Ada@Gmail.com", email_verified: true }),
      })
    );
    const target = await integrationService.completeGmailConnect({ code: "code123", state: goodState(), req });
    const url = new URL(target);
    assert.equal(url.origin + url.pathname, "https://www.sigsignature.com/settings");
    assert.equal(url.searchParams.get("integration"), "gmail");
    assert.equal(url.searchParams.get("status"), "connected");

    assert.equal(connections.length, 1);
    assert.equal(connections[0].accountEmail, "ada@gmail.com");
    assert.ok(!connections[0].refreshTokenEnc.includes("1//refresh"));
    assert.equal(tokenCrypto.decrypt(connections[0].refreshTokenEnc), "1//refresh");
  });

  test("reports a missing permission when the scope was not granted", async () => {
    mockFetch(async () =>
      jsonResponse(200, {
        access_token: "a",
        refresh_token: "r",
        scope: "openid email",
        id_token: idToken({ email: "ada@gmail.com", email_verified: true }),
      })
    );
    const target = new URL(await integrationService.completeGmailConnect({ code: "c", state: goodState(), req }));
    assert.equal(target.searchParams.get("status"), "error");
    assert.equal(target.searchParams.get("reason"), "permission_missing");
    assert.equal(connections.length, 0);
  });

  test("treats a closed consent screen as cancelled", async () => {
    const target = new URL(await integrationService.completeGmailConnect({ error: "access_denied", state: goodState(), req }));
    assert.equal(target.searchParams.get("status"), "cancelled");
  });

  test("refuses an invalid state without calling Google", async () => {
    mockFetch(async () => jsonResponse(200, {}));
    const target = new URL(await integrationService.completeGmailConnect({ code: "c", state: "forged", req }));
    assert.equal(target.searchParams.get("reason"), "invalid_state");
    assert.equal(fetchCalls.length, 0);
  });
});

describe("push signature", () => {
  async function seedConnection(email = "ada@gmail.com") {
    await emailRepoMock.replaceForUser({
      userId: USER_ID,
      provider: "gmail",
      accountEmail: email,
      refreshTokenEnc: tokenCrypto.encrypt("1//refresh"),
      scopes: gmailService.GMAIL_SCOPE,
    });
  }

  test("sends the cleaned html to the signed in user's own address", async () => {
    await seedConnection("ada+work@gmail.com");
    mockFetch(async (url) => {
      if (url.startsWith("https://oauth2.googleapis.com/token")) return jsonResponse(200, { access_token: "ya29.fresh" });
      return jsonResponse(200, {});
    });

    const result = await integrationService.pushGmailSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: GOOD_HTML });
    assert.equal(result.accountEmail, "ada+work@gmail.com");

    const patch = fetchCalls.find((c) => c.init.method === "PATCH");
    assert.equal(
      patch.url,
      "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs/ada%2Bwork%40gmail.com"
    );
    assert.equal(patch.init.headers.Authorization, "Bearer ya29.fresh");
    assert.match(JSON.parse(patch.init.body).signature, /Ada Lovelace/);
    assert.equal(connections[0].lastSignatureId, SIGNATURE_ID);
  });

  test("refuses a signature that belongs to someone else", async () => {
    await seedConnection();
    mockFetch(async () => jsonResponse(200, {}));
    await assert.rejects(
      integrationService.pushGmailSignature({ userId: "other-user", signatureId: SIGNATURE_ID, html: GOOD_HTML }),
      (error) => error.statusCode === 404
    );
    assert.equal(fetchCalls.length, 0);
  });

  test("asks to connect first when there is no connection", async () => {
    mockFetch(async () => jsonResponse(200, {}));
    await assert.rejects(
      integrationService.pushGmailSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: GOOD_HTML }),
      (error) => error.code === "GMAIL_NOT_CONNECTED"
    );
  });

  test("removes the connection and asks to reconnect when Google revoked access", async () => {
    await seedConnection();
    mockFetch(async () => jsonResponse(400, { error: "invalid_grant" }));
    await assert.rejects(
      integrationService.pushGmailSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: GOOD_HTML }),
      (error) => error.code === "GMAIL_RECONNECT_REQUIRED" && error.statusCode === 409
    );
    assert.equal(connections.length, 0);
  });

  test("maps a Gmail 403 to reconnect and a 429 to rate limited", async () => {
    await seedConnection();
    mockFetch(async (url) => (url.includes("oauth2") ? jsonResponse(200, { access_token: "a" }) : jsonResponse(403, {})));
    await assert.rejects(
      integrationService.pushGmailSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: GOOD_HTML }),
      (error) => error.code === "GMAIL_RECONNECT_REQUIRED"
    );

    await seedConnection();
    mockFetch(async (url) => (url.includes("oauth2") ? jsonResponse(200, { access_token: "a" }) : jsonResponse(429, {})));
    await assert.rejects(
      integrationService.pushGmailSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: GOOD_HTML }),
      (error) => error.statusCode === 429
    );
    assert.equal(connections.length, 1);
  });
});

describe("status and disconnect", () => {
  test("never exposes the stored token and disconnect removes it", async () => {
    await emailRepoMock.replaceForUser({
      userId: USER_ID,
      provider: "gmail",
      accountEmail: "ada@gmail.com",
      refreshTokenEnc: tokenCrypto.encrypt("1//refresh"),
      scopes: "x",
    });
    const status = await integrationService.getGmailStatus(USER_ID);
    assert.equal(status.connected, true);
    assert.equal(status.connection.accountEmail, "ada@gmail.com");
    assert.ok(!JSON.stringify(status).includes("refresh"));

    mockFetch(async () => jsonResponse(200, {}));
    const result = await integrationService.disconnectGmail(USER_ID);
    assert.equal(result.disconnected, true);
    assert.ok(fetchCalls.some((c) => c.url.includes("oauth2.googleapis.com/revoke")));
    assert.equal((await integrationService.getGmailStatus(USER_ID)).connected, false);
  });
});
