const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

process.env.NODE_ENV = "test";
process.env.RESEND_API_KEY = process.env.RESEND_API_KEY || "re_test_key";
process.env.JWT_ACCESS_SECRET = "test-access-secret-1234567890";
process.env.ZOHO_CLIENT_ID = "1000.TESTCLIENT";
process.env.ZOHO_CLIENT_SECRET = "zoho-secret";
process.env.INTEGRATION_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
process.env.BACKEND_URL = "https://api.example.test";

const connections = [];
const signatures = new Map();

const repoMock = {
  async findByUser(userId, provider) {
    return connections.filter((c) => c.userId === userId && c.provider === provider);
  },
  async findWithTokenByUser(userId, provider) {
    return connections.find((c) => c.userId === userId && c.provider === provider) || null;
  },
  async replaceForUser({ userId, provider, accountEmail, refreshTokenEnc, scopes, metadata }) {
    for (let i = connections.length - 1; i >= 0; i -= 1) {
      if (connections[i].userId === userId && connections[i].provider === provider) connections.splice(i, 1);
    }
    const row = { id: `c${connections.length + 1}`, userId, provider, accountEmail, refreshTokenEnc, scopes, metadata, createdAt: new Date() };
    connections.push(row);
    return row;
  },
  async saveMetadata(id, metadata) {
    const row = connections.find((c) => c.id === id);
    if (row) row.metadata = metadata;
    return row;
  },
  async markPushed(id, signatureId) {
    const row = connections.find((c) => c.id === id);
    if (row) {
      row.lastPushedAt = new Date();
      row.lastSignatureId = signatureId;
    }
    return row;
  },
  async deleteById(id) {
    const i = connections.findIndex((c) => c.id === id);
    if (i >= 0) connections.splice(i, 1);
  },
  async deleteByUser(userId, provider) {
    let n = 0;
    for (let i = connections.length - 1; i >= 0; i -= 1) {
      if (connections[i].userId === userId && connections[i].provider === provider) {
        connections.splice(i, 1);
        n += 1;
      }
    }
    return n;
  },
};
const sigRepoMock = {
  async findByIdForUser(id, userId) {
    const s = signatures.get(id);
    return s && s.userId === userId ? s : null;
  },
};
function installMock(path, exp) {
  const resolved = require.resolve(path);
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exp };
}
installMock("../src/repositories/email-connection.repository", repoMock);
installMock("../src/repositories/signature.repository", sigRepoMock);

const tokenCrypto = require("../src/utils/tokenCrypto");
const zohoService = require("../src/services/zoho.service");
const integrationService = require("../src/services/integration.service");

const USER_ID = "11111111-1111-4111-8111-111111111111";
const SIGNATURE_ID = "22222222-2222-4222-8222-222222222222";
const HTML = '<table><tr><td><b>Ada</b> <img src="https://cdn.example.com/a.png" width="40"/></td></tr></table>';
const req = { headers: {}, protocol: "https", get: () => "api.example.test" };

const realFetch = global.fetch;
let calls;
function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}
function mockFetch(handler) {
  calls = [];
  global.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init, method: init.method || "GET" });
    return handler(String(url), init);
  };
}

beforeEach(() => {
  connections.length = 0;
  signatures.clear();
  signatures.set(SIGNATURE_ID, { id: SIGNATURE_ID, userId: USER_ID });
});
afterEach(() => {
  global.fetch = realFetch;
});

async function seed(dc = "eu", metadata) {
  await repoMock.replaceForUser({
    userId: USER_ID,
    provider: "zoho",
    accountEmail: "ada@zylker.com",
    refreshTokenEnc: tokenCrypto.encrypt("1000.refresh"),
    scopes: "x",
    metadata: JSON.stringify(metadata || { dc }),
  });
}

describe("data center handling", () => {
  test("only ever resolves to known Zoho hosts", () => {
    assert.equal(zohoService.resolveDataCenter({ accountsServer: "https://accounts.zoho.eu/" }), "eu");
    assert.equal(zohoService.resolveDataCenter({ accountsServer: "https://accounts.zohocloud.ca" }), "ca");
    assert.equal(zohoService.resolveDataCenter({ location: "in" }), "in");
    assert.equal(zohoService.resolveDataCenter({ location: "au" }), "com.au");
    assert.equal(zohoService.resolveDataCenter({ location: "us" }), "com");
    // attacker supplied hosts and junk fall back to the default, never to a custom URL
    assert.equal(zohoService.resolveDataCenter({ accountsServer: "https://accounts.zoho.com.evil.test" }), "com");
    assert.equal(zohoService.resolveDataCenter({ location: "__proto__" }), "com");
    assert.equal(zohoService.resolveDataCenter({}), "com");
  });

  test("auth url asks for offline access and only the account signature scopes", () => {
    const url = new URL(zohoService.buildAuthUrl({ state: "abc", req }));
    assert.equal(url.origin + url.pathname, "https://accounts.zoho.com/oauth/v2/auth");
    assert.equal(url.searchParams.get("access_type"), "offline");
    assert.equal(url.searchParams.get("prompt"), "consent");
    assert.equal(url.searchParams.get("scope"), "ZohoMail.accounts.READ,ZohoMail.accounts.CREATE,ZohoMail.accounts.UPDATE");
    assert.equal(url.searchParams.get("redirect_uri"), "https://api.example.test/api/v1/integrations/zoho/callback");
  });
});

describe("connect callback", () => {
  const goodState = () => integrationService.signState({ userId: USER_ID, frontendOrigin: "https://www.sigsignature.com", provider: "zoho" });

  test("exchanges the code on the user's data center and stores an encrypted token plus the region", async () => {
    mockFetch(async (url) => {
      if (url.includes("/oauth/v2/token")) return json(200, { access_token: "at", refresh_token: "1000.refresh" });
      if (url.endsWith("/api/accounts")) return json(200, { data: [{ accountId: "1", primaryEmailAddress: "Ada@Zylker.com" }] });
      return json(500, {});
    });
    const target = new URL(
      await integrationService.completeZohoConnect({ code: "c", state: goodState(), accountsServer: "https://accounts.zoho.eu", location: "eu", req })
    );
    assert.equal(target.searchParams.get("integration"), "zoho");
    assert.equal(target.searchParams.get("status"), "connected");
    assert.ok(calls[0].url.startsWith("https://accounts.zoho.eu/oauth/v2/token"));
    assert.ok(calls[1].url.startsWith("https://mail.zoho.eu/api/accounts"));
    assert.equal(connections[0].accountEmail, "ada@zylker.com");
    assert.equal(JSON.parse(connections[0].metadata).dc, "eu");
    assert.ok(!connections[0].refreshTokenEnc.includes("1000.refresh"));
    assert.equal(tokenCrypto.decrypt(connections[0].refreshTokenEnc), "1000.refresh");
  });

  test("handles Zoho answering 200 with an error, a missing refresh token, denial and a forged state", async () => {
    mockFetch(async () => json(200, { error: "invalid_code" }));
    let target = new URL(await integrationService.completeZohoConnect({ code: "c", state: goodState(), req }));
    assert.equal(target.searchParams.get("reason"), "failed");

    mockFetch(async () => json(200, { access_token: "at" }));
    target = new URL(await integrationService.completeZohoConnect({ code: "c", state: goodState(), req }));
    assert.equal(target.searchParams.get("reason"), "no_refresh_token");

    target = new URL(await integrationService.completeZohoConnect({ error: "access_denied", state: goodState(), req }));
    assert.equal(target.searchParams.get("status"), "cancelled");

    const gmailState = integrationService.signState({ userId: USER_ID, frontendOrigin: "https://www.sigsignature.com" });
    mockFetch(async () => json(200, {}));
    target = new URL(await integrationService.completeZohoConnect({ code: "c", state: gmailState, req }));
    assert.equal(target.searchParams.get("reason"), "invalid_state");
    assert.equal(calls.length, 0);
    assert.equal(connections.length, 0);
  });
});

describe("push signature", () => {
  test("creates the signature when none exists and assigns it to the mailbox", async () => {
    await seed("eu");
    mockFetch(async (url, init) => {
      if (url.includes("/oauth/v2/token")) return json(200, { access_token: "fresh" });
      if (url.endsWith("/api/accounts/signature") && init.method === "GET") return json(200, { data: [{ id: "9", name: "Other" }] });
      if (url.endsWith("/api/accounts/signature") && init.method === "POST") return json(201, { data: { id: "777" } });
      return json(500, {});
    });
    const result = await integrationService.pushZohoSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: HTML });
    assert.equal(result.accountEmail, "ada@zylker.com");
    const post = calls.find((c) => c.method === "POST" && c.url.includes("/api/accounts/signature"));
    assert.ok(post.url.startsWith("https://mail.zoho.eu/"));
    assert.equal(post.init.headers.Authorization, "Zoho-oauthtoken fresh");
    const body = JSON.parse(post.init.body);
    assert.equal(body.name, "Sig Signature");
    assert.equal(body.assignUsers, "ada@zylker.com");
    assert.match(body.content, /Ada/);
    assert.equal(JSON.parse(connections[0].metadata).signatureId, "777");
    assert.equal(JSON.parse(connections[0].metadata).dc, "eu");
  });

  test("updates the existing signature instead of creating duplicates", async () => {
    await seed("com", { dc: "com", signatureId: "777" });
    mockFetch(async (url, init) => {
      if (url.includes("/oauth/v2/token")) return json(200, { access_token: "fresh" });
      if (url.endsWith("/api/accounts/signature") && init.method === "GET") return json(200, { data: [{ id: "777", name: "Sig Signature" }] });
      if (init.method === "PUT") return json(200, { data: { id: "777" } });
      return json(500, {});
    });
    await integrationService.pushZohoSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: HTML });
    assert.ok(!calls.some((c) => c.method === "POST" && c.url.includes("/api/accounts/signature")));
    const put = calls.find((c) => c.method === "PUT");
    assert.equal(JSON.parse(put.init.body).id, "777");
  });

  test("guards: not connected, not owner, embedded image", async () => {
    mockFetch(async () => json(200, {}));
    await assert.rejects(integrationService.pushZohoSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: HTML }), (e) => e.code === "ZOHO_NOT_CONNECTED");
    await seed();
    await assert.rejects(integrationService.pushZohoSignature({ userId: "other", signatureId: SIGNATURE_ID, html: HTML }), (e) => e.statusCode === 404);
    await assert.rejects(
      integrationService.pushZohoSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: '<img src="data:image/png;base64,AAAA"/>' }),
      (e) => e.code === "GMAIL_EMBEDDED_IMAGE"
    );
    assert.equal(calls.length, 0);
  });

  test("removes the connection and asks to reconnect when Zoho revoked access", async () => {
    await seed();
    mockFetch(async () => json(400, { error: "invalid_code" }));
    await assert.rejects(
      integrationService.pushZohoSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: HTML }),
      (e) => e.code === "ZOHO_RECONNECT_REQUIRED" && e.statusCode === 409
    );
    assert.equal(connections.length, 0);
  });

  test("maps 429 to rate limited and keeps the connection", async () => {
    await seed();
    mockFetch(async (url) => (url.includes("/oauth/v2/token") ? json(200, { access_token: "a" }) : json(429, {})));
    await assert.rejects(integrationService.pushZohoSignature({ userId: USER_ID, signatureId: SIGNATURE_ID, html: HTML }), (e) => e.statusCode === 429);
    assert.equal(connections.length, 1);
  });
});

describe("status and disconnect", () => {
  test("status hides secrets and disconnect revokes on the right data center", async () => {
    await seed("in");
    const status = await integrationService.getZohoStatus(USER_ID);
    assert.equal(status.connected, true);
    assert.ok(!JSON.stringify(status).includes("refresh"));

    mockFetch(async () => json(200, {}));
    assert.equal((await integrationService.disconnectZoho(USER_ID)).disconnected, true);
    assert.ok(calls[0].url.startsWith("https://accounts.zoho.in/oauth/v2/token/revoke"));
    assert.equal((await integrationService.getZohoStatus(USER_ID)).connected, false);
  });
});
