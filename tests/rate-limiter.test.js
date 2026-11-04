const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  MemoryStore,
  setStore,
  loginLimiter,
  signupLimiter,
  forgotPasswordLimiter,
  calculateLockoutSeconds,
} = require("../src/middleware/rateLimiter.middleware");
const { validate } = require("../src/middleware/validate.middleware");
const {
  loginSchema,
  forgotPasswordSchema,
  signupSchema,
} = require("../src/validators/auth.validator");

/**
 * Lightweight mock Express request/response pipeline.
 * Runs without network sockets so tests execute safely within any sandbox environment.
 */
function runPipeline(middlewares, { ip = "127.0.0.1", body = {}, headers = {}, handler = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = {
      ip,
      headers: { ...headers },
      body: JSON.parse(JSON.stringify(body)),
      socket: { remoteAddress: ip },
    };

    const resHeaders = {};
    let statusCode = 200;
    let responseBody = null;
    const finishListeners = [];

    const res = {
      statusCode: 200,
      setHeader(name, value) {
        resHeaders[name.toLowerCase()] = String(value);
      },
      getHeader(name) {
        return resHeaders[name.toLowerCase()];
      },
      status(code) {
        statusCode = code;
        res.statusCode = code;
        return res;
      },
      json(data) {
        responseBody = data;
        res.emitFinish();
        resolve({
          status: statusCode,
          headers: resHeaders,
          body: responseBody,
        });
        return res;
      },
      on(event, listener) {
        if (event === "finish") {
          finishListeners.push(listener);
        }
      },
      emitFinish() {
        for (const fn of finishListeners) {
          try {
            fn();
          } catch (e) {
            console.error("Error in finish listener:", e);
          }
        }
      },
    };

    let idx = 0;
    function dispatchNext(err) {
      if (err) return reject(err);
      if (idx < middlewares.length) {
        const mw = middlewares[idx++];
        try {
          mw(req, res, dispatchNext);
        } catch (e) {
          reject(e);
        }
      } else if (handler) {
        try {
          handler(req, res);
        } catch (e) {
          reject(e);
        }
      } else {
        res.status(200).json({ success: true });
      }
    }

    dispatchNext();
  });
}

describe("Rate Limiter Suite", () => {
  let testStore;

  // Mock credential verification handler
  function loginHandler(req, res) {
    const { email, password } = req.body;
    if (password === "CorrectPassword123!") {
      return res.status(200).json({
        success: true,
        message: "Login successful",
        user: { email },
      });
    }
    return res.status(401).json({
      success: false,
      message: "Invalid email or password",
    });
  }

  beforeEach(() => {
    testStore = new MemoryStore();
    setStore(testStore);
  });

  afterEach(() => {
    delete process.env.TURNSTILE_SECRET_KEY;
    testStore.destroy();
  });

  // -------------------------------------------------------------------------
  // Progressive lockout calculation unit test
  // -------------------------------------------------------------------------
  test("calculateLockoutSeconds follows the required progression", () => {
    assert.equal(calculateLockoutSeconds(0), 0);
    assert.equal(calculateLockoutSeconds(19), 0);
    assert.equal(calculateLockoutSeconds(20), 30); // 30s
    assert.equal(calculateLockoutSeconds(21), 60); // 1m
    assert.equal(calculateLockoutSeconds(22), 120); // 2m
    assert.equal(calculateLockoutSeconds(23), 240); // 4m
    assert.equal(calculateLockoutSeconds(24), 480); // 8m
    assert.equal(calculateLockoutSeconds(25), 900); // 15m maximum
    assert.equal(calculateLockoutSeconds(30), 900); // capped at 15m
  });

  // -------------------------------------------------------------------------
  // 1. 10 different accounts from one IP all succeed
  // -------------------------------------------------------------------------
  test("1. 10 different accounts from one IP all succeed without lockout", async () => {
    const sharedIp = "198.51.100.1";

    for (let i = 1; i <= 10; i++) {
      const email = `employee${i}@company.com`;
      const res = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip: sharedIp,
          body: {
            email,
            password: "CorrectPassword123!",
          },
          handler: loginHandler,
        }
      );

      assert.equal(
        res.status,
        200,
        `Expected 200 for user ${i}, but got ${res.status}`
      );
      assert.equal(res.body.success, true);
    }
  });

  // -------------------------------------------------------------------------
  // 2. 20 wrong passwords for one account triggers progressive lockout (429)
  // -------------------------------------------------------------------------
  test("2. 20 wrong passwords for one account triggers progressive lockout (429)", async () => {
    const ip = "198.51.100.2";
    const email = "lockout-test@example.com";

    // First 20 attempts with wrong password should fail with 401
    for (let i = 1; i <= 20; i++) {
      const res = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip,
          body: {
            email,
            password: "WrongPassword999!",
          },
          handler: loginHandler,
        }
      );

      assert.equal(
        res.status,
        401,
        `Expected 401 on attempt ${i}, got ${res.status}`
      );
    }

    // 21st attempt should be blocked by progressive lockout with 429
    const blockedRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip,
        body: {
          email,
          password: "WrongPassword999!",
        },
        handler: loginHandler,
      }
    );

    assert.equal(blockedRes.status, 429);
    assert.ok(blockedRes.headers["retry-after"]);
    assert.equal(blockedRes.headers["x-ratelimit-limit"], "20");
    assert.equal(blockedRes.headers["x-ratelimit-remaining"], "0");

    assert.equal(blockedRes.body.success, false);
    assert.equal(blockedRes.body.code, "LOGIN_RATE_LIMITED");
    assert.match(blockedRes.body.message, /Too many login attempts\. Please try again in .* or reset your password\./);
    assert.ok(
      blockedRes.body.retryAfterSeconds > 0 && blockedRes.body.retryAfterSeconds <= 30
    );
  });

  // -------------------------------------------------------------------------
  // 3. A correct login after a lockout window works
  // -------------------------------------------------------------------------
  test("3. A correct login after the lockout window elapses works", async () => {
    const ip = "198.51.100.3";
    const email = "window-test@example.com";

    // Cause 20 failures
    for (let i = 1; i <= 20; i++) {
      await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip,
          body: {
            email,
            password: "WrongPassword999!",
          },
          handler: loginHandler,
        }
      );
    }

    // Confirm user is locked out
    const lockedRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip,
        body: {
          email,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );
    assert.equal(lockedRes.status, 429);

    // Simulate lockout expiration by setting lockedUntil in store to past
    const ipEmailKey = `login:ip_email:${ip}:${email}`;
    const record = await testStore.get(ipEmailKey);
    assert.ok(record);
    await testStore.set(
      ipEmailKey,
      {
        ...record,
        lockedUntil: Date.now() - 1000, // 1 second in the past
      },
      60 * 1000
    );

    // Attempt login with correct password after lockout elapsed
    const successRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip,
        body: {
          email,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );

    assert.equal(successRes.status, 200);
    assert.equal(successRes.body.success, true);
  });

  // -------------------------------------------------------------------------
  // 4. A success resets the counter
  // -------------------------------------------------------------------------
  test("4. A successful login resets the failure counter", async () => {
    const ip = "198.51.100.4";
    const email = "reset-test@example.com";

    // 19 failed attempts (1 away from lockout)
    for (let i = 1; i <= 19; i++) {
      const res = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip,
          body: {
            email,
            password: "WrongPassword!",
          },
          handler: loginHandler,
        }
      );
      assert.equal(res.status, 401);
    }

    // 20th attempt is successful
    const loginRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip,
        body: {
          email,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );
    assert.equal(loginRes.status, 200);

    // Store record for this IP+email should have been reset
    const ipEmailKey = `login:ip_email:${ip}:${email}`;
    const cleared = await testStore.get(ipEmailKey);
    assert.equal(cleared, null);

    // Now, user should have a fresh set of 19 attempts without being locked out
    for (let i = 1; i <= 19; i++) {
      const res = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip,
          body: {
            email,
            password: "WrongAgain!",
          },
          handler: loginHandler,
        }
      );
      assert.equal(res.status, 401, `Attempt ${i} after reset should be 401, not 429`);
    }
  });

  // -------------------------------------------------------------------------
  // 5. A different IP can still log in to the same account until the per email cap
  // -------------------------------------------------------------------------
  test("5. A different IP can still log in to the same account until the per-email cap (50 failures)", async () => {
    const ip1 = "198.51.100.51";
    const ip2 = "198.51.100.52";
    const email = "shared-target@example.com";

    // IP 1 fails 20 times and gets locked out
    for (let i = 1; i <= 20; i++) {
      await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip: ip1,
          body: {
            email,
            password: "WrongPassword!",
          },
          handler: loginHandler,
        }
      );
    }

    const ip1Blocked = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip: ip1,
        body: {
          email,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );
    assert.equal(ip1Blocked.status, 429, "IP 1 should be locked out");

    // IP 2 attempts login to the SAME account with correct password -> must succeed!
    const ip2Success = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip: ip2,
        body: {
          email,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );
    assert.equal(
      ip2Success.status,
      200,
      "IP 2 should successfully log in despite IP 1 lockout"
    );

    // Now test the global per-email cap of 50 failures across distributed IPs
    const distEmail = "distributed-target@example.com";
    for (let i = 1; i <= 50; i++) {
      const randomIp = `10.0.1.${i}`;
      const failRes = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip: randomIp,
          body: {
            email: distEmail,
            password: "GuessPassword!",
          },
          handler: loginHandler,
        }
      );
      assert.equal(failRes.status, 401);
    }

    // 51st attempt from a brand new IP should trigger the per-email cap 429
    const newIp = "10.0.2.99";
    const emailCappedRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip: newIp,
        body: {
          email: distEmail,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );

    assert.equal(emailCappedRes.status, 429);
    assert.equal(emailCappedRes.body.code, "LOGIN_RATE_LIMITED");
    assert.match(emailCappedRes.body.message, /Too many login attempts\. Please try again in .* or reset your password\./);
  });

  // -------------------------------------------------------------------------
  // 6. Turnstile Hook
  // -------------------------------------------------------------------------
  test("6. Turnstile hook disabled when TURNSTILE_SECRET_KEY unset; enabled when set", async () => {
    const ip = "198.51.100.6";
    const email = "turnstile-test@example.com";

    // Without TURNSTILE_SECRET_KEY, 5th failure does not include captchaRequired
    for (let i = 1; i <= 5; i++) {
      const res = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip,
          body: {
            email,
            password: "WrongPassword!",
          },
          handler: loginHandler,
        }
      );
      assert.equal(res.body.captchaRequired, undefined);
    }

    // Now set TURNSTILE_SECRET_KEY
    process.env.TURNSTILE_SECRET_KEY = "dummy_secret_key";
    const ipTurnstile = "198.51.100.7";
    const emailTurnstile = "turnstile-enabled@example.com";

    // First 4 failures do not request captcha
    for (let i = 1; i <= 4; i++) {
      const res = await runPipeline(
        [validate(loginSchema), loginLimiter],
        {
          ip: ipTurnstile,
          body: {
            email: emailTurnstile,
            password: "WrongPassword!",
          },
          handler: loginHandler,
        }
      );
      assert.equal(res.status, 401);
      assert.equal(res.body.captchaRequired, undefined);
    }

    // 5th failure response must include captchaRequired: true
    const fifthRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip: ipTurnstile,
        body: {
          email: emailTurnstile,
          password: "WrongPassword!",
        },
        handler: loginHandler,
      }
    );
    assert.equal(fifthRes.status, 401);
    assert.equal(fifthRes.body.captchaRequired, true);

    // Simulate lockout expiration
    const key = `login:ip_email:${ipTurnstile}:${emailTurnstile}`;
    const rec = await testStore.get(key);
    await testStore.set(key, { ...rec, lockedUntil: Date.now() - 1000 }, 60000);

    // Next login without turnstile token is rejected with 401 and captchaRequired
    const noTokenRes = await runPipeline(
      [validate(loginSchema), loginLimiter],
      {
        ip: ipTurnstile,
        body: {
          email: emailTurnstile,
          password: "CorrectPassword123!",
        },
        handler: loginHandler,
      }
    );
    assert.equal(noTokenRes.status, 401);
    assert.equal(noTokenRes.body.captchaRequired, true);
    assert.equal(noTokenRes.body.code, "CAPTCHA_REQUIRED");
  });

  // -------------------------------------------------------------------------
  // 7. Forgot password rate limiting
  // -------------------------------------------------------------------------
  test("7. Forgot password limits 3 requests per 15 minutes per email", async () => {
    const ip = "198.51.100.8";
    const email = "forgot@example.com";

    function forgotHandler(req, res) {
      return res.status(200).json({ success: true, message: "Reset link sent" });
    }

    for (let i = 1; i <= 3; i++) {
      const res = await runPipeline(
        [validate(forgotPasswordSchema), forgotPasswordLimiter],
        {
          ip,
          body: { email },
          handler: forgotHandler,
        }
      );
      assert.equal(res.status, 200, `Forgot password request ${i} should succeed`);
    }

    // 4th request for same email gets 429
    const blockedRes = await runPipeline(
      [validate(forgotPasswordSchema), forgotPasswordLimiter],
      {
        ip,
        body: { email },
        handler: forgotHandler,
      }
    );
    assert.equal(blockedRes.status, 429);
    assert.ok(blockedRes.headers["retry-after"]);

    // Different email from same IP still succeeds
    const otherEmailRes = await runPipeline(
      [validate(forgotPasswordSchema), forgotPasswordLimiter],
      {
        ip,
        body: { email: "other@example.com" },
        handler: forgotHandler,
      }
    );
    assert.equal(otherEmailRes.status, 200);
  });

  // -------------------------------------------------------------------------
  // 8. Signup limiter (30 per hour)
  // -------------------------------------------------------------------------
  test("8. Signup limiter allows up to 30 signups per hour per IP", async () => {
    const ip = "198.51.100.9";

    function signupHandler(req, res) {
      return res.status(201).json({ success: true, message: "Signed up" });
    }

    // 30 signups from same IP succeed
    for (let i = 1; i <= 30; i++) {
      const res = await runPipeline(
        [signupLimiter, validate(signupSchema)],
        {
          ip,
          body: {
            firstName: "John",
            lastName: "Doe",
            email: `user${i}@office.com`,
            password: "ValidPassword123!",
          },
          handler: signupHandler,
        }
      );
      assert.equal(res.status, 201, `Signup ${i} should succeed`);
    }

    // 31st signup gets 429
    const blockedRes = await runPipeline(
      [signupLimiter, validate(signupSchema)],
      {
        ip,
        body: {
          firstName: "John",
          lastName: "Doe",
          email: "user31@office.com",
          password: "ValidPassword123!",
        },
        handler: signupHandler,
      }
    );
    assert.equal(blockedRes.status, 429);
    assert.equal(blockedRes.body.code, "SIGNUP_RATE_LIMITED");
  });

  // -------------------------------------------------------------------------
  // 9. Invalid body fallback to IP only
  // -------------------------------------------------------------------------
  test("9. Invalid body falls back to IP-only rate limiting", async () => {
    const ip = "198.51.100.10";

    // When body is missing email, loginLimiter should not crash and fall back to IP
    const res = await runPipeline(
      [loginLimiter],
      {
        ip,
        body: {},
        handler: (req, res) => res.status(400).json({ success: false, message: "No email" }),
      }
    );
    assert.equal(res.status, 400);
  });
});
