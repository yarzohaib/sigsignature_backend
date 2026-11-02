/**
 * Account-Aware Rate Limiting Middleware
 *
 * Implements layered protection for sensitive authentication endpoints:
 * 1. Per-IP Flood Protection: Generous request cap across shared office / VPN networks.
 * 2. Account-Aware Failure Limiting: Tracks credential failures per (IP + email) with
 *    progressive exponential backoff lockout (30s, 1m, 2m, 4m, 8m, max 15m).
 * 3. Distributed Account Brute-Force Protection: Global per-email failure cap across all IPs.
 * 4. Optional Cloudflare Turnstile Verification: Enforces CAPTCHA after repeated failures.
 *
 * STORE INTERFACE SPECIFICATION:
 * All limiters operate over a standard RateLimitStore interface:
 *   - get(key: string): Promise<Record | null>
 *   - increment(key: string, ttlMs: number): Promise<{ count: number, resetAt: number }>
 *   - set(key: string, value: any, ttlMs: number): Promise<void>
 *   - reset(key: string): Promise<void>
 *
 * NOTE FOR MULTI-SERVER / CLUSTER MODE:
 * The default MemoryStore is process-local. When running Express in Node.js cluster mode
 * or behind a load balancer with multiple backend instances, replace this store with
 * a shared distributed store (such as Redis with atomic INCR/EXPIRE or a Redis-backed
 * implementation of this interface via `setStore(new RedisStore())`) so rate limits and
 * lockouts are synchronized across all worker processes.
 */

class MemoryStore {
  constructor(cleanupIntervalMs = 60 * 1000) {
    this.map = new Map();
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, cleanupIntervalMs);

    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.map.entries()) {
      if (record && record.resetAt <= now) {
        this.map.delete(key);
      }
    }
  }

  async get(key) {
    const record = this.map.get(key);
    if (!record) return null;
    if (record.resetAt <= Date.now()) {
      this.map.delete(key);
      return null;
    }
    return record;
  }

  async increment(key, ttlMs) {
    const now = Date.now();
    let record = this.map.get(key);
    if (!record || record.resetAt <= now) {
      record = {
        count: 1,
        resetAt: now + ttlMs,
      };
      this.map.set(key, record);
    } else {
      record.count += 1;
    }
    return { count: record.count, resetAt: record.resetAt };
  }

  async set(key, value, ttlMs) {
    const now = Date.now();
    const resetAt = now + ttlMs;
    const record = {
      ...value,
      resetAt,
    };
    this.map.set(key, record);
    return record;
  }

  async reset(key) {
    this.map.delete(key);
  }

  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.map.clear();
  }
}

// Active store singleton (swappable for Redis in cluster deployments or unit tests)
let activeStore = new MemoryStore();

function setStore(store) {
  activeStore = store;
}

function getStore() {
  return activeStore;
}

/**
 * Helper to resolve the client IP address from Express req
 */
function getClientIp(req) {
  if (req.ip) return req.ip;
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const parts = String(forwarded).split(",");
    if (parts.length > 0) return parts[0].trim();
  }
  return req.socket?.remoteAddress || "127.0.0.1";
}

/**
 * Calculates progressive lockout duration in seconds based on consecutive failures:
 * - < 5 failures: 0s (no lockout)
 * - 5 failures: 30s
 * - 6 failures: 60s (1m)
 * - 7 failures: 120s (2m)
 * - 8 failures: 240s (4m)
 * - 9 failures: 480s (8m)
 * - 10+ failures: 900s (15m maximum)
 */
function calculateLockoutSeconds(failures) {
  if (failures < 5) return 0;
  const exponent = failures - 5;
  const seconds = 30 * Math.pow(2, exponent);
  return Math.min(900, Math.floor(seconds));
}

// ---------------------------------------------------------------------------
// 1. Account-Aware Login Rate Limiter (3 Layers)
// ---------------------------------------------------------------------------
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const LOGIN_IP_FLOOD_MAX = 300; // 300 requests in 15 min per IP
const LOGIN_EMAIL_FAILURES_MAX = 20; // 20 failures in 15 min per email across all IPs
const LOGIN_FAILURES_BEFORE_LOCKOUT = 5; // 5 failures before progressive lockout
const GENERIC_LOGIN_RATE_LIMIT_MSG = "Too many login attempts. Please try again later.";

async function loginLimiter(req, res, next) {
  const ip = getClientIp(req);
  const email =
    typeof req.body?.email === "string" && req.body.email.trim()
      ? req.body.email.trim().toLowerCase()
      : null;

  const store = getStore();
  const now = Date.now();

  // Layer 3: Per-IP Flood Protection (300 requests in 15 minutes)
  const ipKey = `login:ip:${ip}`;
  const ipRecord = await store.increment(ipKey, LOGIN_WINDOW_MS);
  if (ipRecord.count > LOGIN_IP_FLOOD_MAX) {
    const retryAfterSeconds = Math.max(1, Math.ceil((ipRecord.resetAt - now) / 1000));
    res.setHeader("Retry-After", retryAfterSeconds);
    res.setHeader("X-RateLimit-Limit", LOGIN_IP_FLOOD_MAX);
    res.setHeader("X-RateLimit-Remaining", 0);
    res.setHeader("X-RateLimit-Reset", Math.ceil(ipRecord.resetAt / 1000));
    return res.status(429).json({
      success: false,
      message: GENERIC_LOGIN_RATE_LIMIT_MSG,
      retryAfterSeconds,
      code: "LOGIN_RATE_LIMITED",
    });
  }

  // If the body is invalid or email is missing, fall back to IP-only protection
  if (!email) {
    const remaining = Math.max(0, LOGIN_IP_FLOOD_MAX - ipRecord.count);
    res.setHeader("X-RateLimit-Limit", LOGIN_IP_FLOOD_MAX);
    res.setHeader("X-RateLimit-Remaining", remaining);
    res.setHeader("X-RateLimit-Reset", Math.ceil(ipRecord.resetAt / 1000));
    return next();
  }

  const ipEmailKey = `login:ip_email:${ip}:${email}`;
  const emailKey = `login:email:${email}`;

  // Layer 1: Check per-(IP + email) progressive lockout
  const ipEmailRecord = await store.get(ipEmailKey);
  if (ipEmailRecord?.lockedUntil && ipEmailRecord.lockedUntil > now) {
    const retryAfterSeconds = Math.max(1, Math.ceil((ipEmailRecord.lockedUntil - now) / 1000));
    res.setHeader("Retry-After", retryAfterSeconds);
    res.setHeader("X-RateLimit-Limit", LOGIN_FAILURES_BEFORE_LOCKOUT);
    res.setHeader("X-RateLimit-Remaining", 0);
    res.setHeader("X-RateLimit-Reset", Math.ceil(ipEmailRecord.lockedUntil / 1000));
    return res.status(429).json({
      success: false,
      message: GENERIC_LOGIN_RATE_LIMIT_MSG,
      retryAfterSeconds,
      code: "LOGIN_RATE_LIMITED",
    });
  }

  // Layer 2: Check per-email failure cap across all IPs (20 failures in 15 minutes)
  const emailRecord = await store.get(emailKey);
  if (emailRecord && emailRecord.count >= LOGIN_EMAIL_FAILURES_MAX) {
    const retryAfterSeconds = Math.max(1, Math.ceil((emailRecord.resetAt - now) / 1000));
    res.setHeader("Retry-After", retryAfterSeconds);
    res.setHeader("X-RateLimit-Limit", LOGIN_EMAIL_FAILURES_MAX);
    res.setHeader("X-RateLimit-Remaining", 0);
    res.setHeader("X-RateLimit-Reset", Math.ceil(emailRecord.resetAt / 1000));
    return res.status(429).json({
      success: false,
      message: GENERIC_LOGIN_RATE_LIMIT_MSG,
      retryAfterSeconds,
      code: "LOGIN_RATE_LIMITED",
    });
  }

  // Optional Cloudflare Turnstile Hook (disabled unless TURNSTILE_SECRET_KEY is set)
  const currentFailures = ipEmailRecord?.count || 0;
  const turnstileSecret = process.env.TURNSTILE_SECRET_KEY;
  if (turnstileSecret && currentFailures >= LOGIN_FAILURES_BEFORE_LOCKOUT) {
    const token =
      req.body?.["cf-turnstile-token"] ||
      req.body?.turnstileToken ||
      req.headers["cf-turnstile-token"];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Captcha verification required. Please complete the captcha.",
        captchaRequired: true,
        code: "CAPTCHA_REQUIRED",
      });
    }

    try {
      const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: turnstileSecret,
          response: String(token),
          remoteip: ip,
        }),
        signal: AbortSignal.timeout(5000),
      });

      const verifyData = await verifyRes.json();
      if (!verifyData.success) {
        return res.status(401).json({
          success: false,
          message: "Captcha verification failed. Please try again.",
          captchaRequired: true,
          code: "CAPTCHA_INVALID",
        });
      }
    } catch (err) {
      console.error("[Turnstile] Verification failed:", err.message || err);
      return res.status(401).json({
        success: false,
        message: "Captcha verification failed. Please try again.",
        captchaRequired: true,
        code: "CAPTCHA_ERROR",
      });
    }
  }

  // Set X-RateLimit headers for the allowed attempt
  const remainingFailures = Math.max(0, LOGIN_FAILURES_BEFORE_LOCKOUT - currentFailures);
  const resetTimestamp = ipEmailRecord?.resetAt || now + LOGIN_WINDOW_MS;
  res.setHeader("X-RateLimit-Limit", LOGIN_FAILURES_BEFORE_LOCKOUT);
  res.setHeader("X-RateLimit-Remaining", remainingFailures);
  res.setHeader("X-RateLimit-Reset", Math.ceil(resetTimestamp / 1000));

  // If Turnstile is active, wrap res.json so that if credentials fail (401)
  // and failures reach 5+, captchaRequired: true is included in the 401 response
  if (turnstileSecret) {
    const originalJson = res.json.bind(res);
    res.json = function (data) {
      if (res.statusCode === 401 && (currentFailures + 1 >= LOGIN_FAILURES_BEFORE_LOCKOUT)) {
        if (data && typeof data === "object") {
          data.captchaRequired = true;
        }
      }
      return originalJson(data);
    };
  }

  // Track outcome when request finishes:
  // - 200 (Success): Reset failure and lockout counters
  // - 401 (Credential Failure): Increment failure counter and apply progressive lockout if threshold reached
  res.on("finish", async () => {
    try {
      if (res.statusCode === 200) {
        // Successful logins must never count toward any failure limit.
        // A successful login resets this counter.
        await store.reset(ipEmailKey);
        await store.reset(emailKey);
      } else if (res.statusCode === 401) {
        // Credentials failed
        const existing = await store.get(ipEmailKey);
        const newFailures = (existing?.count || 0) + 1;
        const lockoutSec = calculateLockoutSeconds(newFailures);
        const lockedUntil = lockoutSec > 0 ? Date.now() + (lockoutSec * 1000) : null;
        const ttlMs = Math.max(LOGIN_WINDOW_MS, (lockoutSec + 60) * 1000);

        await store.set(
          ipEmailKey,
          {
            count: newFailures,
            lockedUntil,
          },
          ttlMs
        );

        // Increment per-email failure counter
        await store.increment(emailKey, LOGIN_WINDOW_MS);
      }
    } catch (err) {
      console.error("[RateLimiter] Error updating store on finish:", err);
    }
  });

  next();
}

// ---------------------------------------------------------------------------
// 2. Account-Aware Rate Limiter for Forgot Password & Verification Requests
// ---------------------------------------------------------------------------
function createAccountAwareRateLimiter({
  windowMs = 15 * 60 * 1000,
  emailMax = 5,
  ipMax = 100, // Generous IP cap for offices/VPNs
  message = "Too many requests. Please try again later.",
  code = "RATE_LIMITED",
  prefix = "auth_req",
} = {}) {
  return async function accountAwareRateLimiter(req, res, next) {
    const ip = getClientIp(req);
    const email =
      typeof req.body?.email === "string" && req.body.email.trim()
        ? req.body.email.trim().toLowerCase()
        : null;

    const store = getStore();
    const now = Date.now();

    // 1. IP Flood Protection (Generous IP cap)
    const ipKey = `${prefix}:ip:${ip}`;
    const ipRecord = await store.increment(ipKey, windowMs);
    if (ipRecord.count > ipMax) {
      const retryAfterSeconds = Math.max(1, Math.ceil((ipRecord.resetAt - now) / 1000));
      res.setHeader("Retry-After", retryAfterSeconds);
      res.setHeader("X-RateLimit-Limit", ipMax);
      res.setHeader("X-RateLimit-Remaining", 0);
      res.setHeader("X-RateLimit-Reset", Math.ceil(ipRecord.resetAt / 1000));
      return res.status(429).json({
        success: false,
        message,
        retryAfterSeconds,
        code,
      });
    }

    // 2. Email-specific limiting (5 per 15 minutes per email)
    if (email) {
      const emailKey = `${prefix}:email:${email}`;
      const emailRecord = await store.increment(emailKey, windowMs);
      const remaining = Math.max(0, emailMax - emailRecord.count);
      const retryAfterSeconds = Math.max(1, Math.ceil((emailRecord.resetAt - now) / 1000));

      res.setHeader("X-RateLimit-Limit", emailMax);
      res.setHeader("X-RateLimit-Remaining", remaining);
      res.setHeader("X-RateLimit-Reset", Math.ceil(emailRecord.resetAt / 1000));

      if (emailRecord.count > emailMax) {
        res.setHeader("Retry-After", retryAfterSeconds);
        return res.status(429).json({
          success: false,
          message,
          retryAfterSeconds,
          code,
        });
      }
    } else {
      // Fallback to IP only if no email is present
      const remaining = Math.max(0, ipMax - ipRecord.count);
      res.setHeader("X-RateLimit-Limit", ipMax);
      res.setHeader("X-RateLimit-Remaining", remaining);
      res.setHeader("X-RateLimit-Reset", Math.ceil(ipRecord.resetAt / 1000));
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// 3. Generic Rate Limiter Factory (Backwards-Compatible with Store Interface)
// ---------------------------------------------------------------------------
function createRateLimiter({
  windowMs = 15 * 60 * 1000,
  max = 10,
  message = "Too many requests. Please try again later.",
  keyGenerator = (req) => getClientIp(req),
  code = "RATE_LIMITED",
} = {}) {
  return async function rateLimiterMiddleware(req, res, next) {
    const key = keyGenerator(req);
    const store = getStore();
    const record = await store.increment(`rl:${key}`, windowMs);
    const now = Date.now();

    const remaining = Math.max(0, max - record.count);
    const retryAfterSeconds = Math.max(1, Math.ceil((record.resetAt - now) / 1000));

    res.setHeader("X-RateLimit-Limit", max);
    res.setHeader("X-RateLimit-Remaining", remaining);
    res.setHeader("X-RateLimit-Reset", Math.ceil(record.resetAt / 1000));

    if (record.count > max) {
      res.setHeader("Retry-After", retryAfterSeconds);
      return res.status(429).json({
        success: false,
        message,
        retryAfterSeconds,
        code,
      });
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Route Limiter Instances
// ---------------------------------------------------------------------------

// 1. Signup limiter: 30 accounts per 1 hour per IP (raised for shared office networks)
const signupLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: "Too many accounts created from this IP. Please try again later.",
  code: "SIGNUP_RATE_LIMITED",
});

// 2. Forgot password limiter: 3 requests per 15 minutes per email (generous IP cap)
const forgotPasswordLimiter = createAccountAwareRateLimiter({
  windowMs: 15 * 60 * 1000,
  emailMax: 3,
  ipMax: 100,
  prefix: "forgot_pwd",
  message: "Too many password reset requests. Please wait 15 minutes before trying again.",
  code: "RATE_LIMITED",
});

// 3. Verification email limiter: 3 requests per 15 minutes per email (generous IP cap)
const resendVerificationLimiter = createAccountAwareRateLimiter({
  windowMs: 15 * 60 * 1000,
  emailMax: 3,
  ipMax: 100,
  prefix: "resend_verif",
  message: "Too many verification requests. Please wait 15 minutes before requesting again.",
  code: "RATE_LIMITED",
});

// 4. General auth endpoints limiter: 60 requests per minute
const generalAuthLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  message: "Too many requests to authentication service. Please slow down.",
  code: "AUTH_RATE_LIMITED",
});

// 5. Upload presign limiter: 30 requests per user per hour
const uploadPresignLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: "Too many upload requests. You may only request up to 30 upload URLs per hour.",
  code: "UPLOAD_RATE_LIMITED",
  keyGenerator: (req) => {
    const userId = req.user?.id || req.user?.sub;
    return userId ? `user:${userId}` : getClientIp(req);
  },
});

// 6. Password change limiter: 10 requests per 15 minutes
const changePasswordLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many password change attempts. Please try again after 15 minutes.",
  code: "PASSWORD_RATE_LIMITED",
  keyGenerator: (req) => {
    const userId = req.user?.id || req.user?.sub;
    return userId ? `pwd:${userId}` : getClientIp(req);
  },
});

// 7. Account export limiter: 3 requests per hour
const accountExportLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: "Too many account export requests. Please try again in an hour.",
  code: "EXPORT_RATE_LIMITED",
  keyGenerator: (req) => {
    const userId = req.user?.id || req.user?.sub;
    return userId ? `export:${userId}` : getClientIp(req);
  },
});

// 8. Account delete limiter: 3 requests per hour
const accountDeleteLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: "Too many account deletion attempts. Please try again later.",
  code: "DELETE_RATE_LIMITED",
  keyGenerator: (req) => {
    const userId = req.user?.id || req.user?.sub;
    return userId ? `delete:${userId}` : getClientIp(req);
  },
});

module.exports = {
  // Store & Utilities
  MemoryStore,
  getStore,
  setStore,
  getClientIp,
  calculateLockoutSeconds,

  // Middleware & Factories
  createRateLimiter,
  createAccountAwareRateLimiter,
  loginLimiter,
  signupLimiter,
  forgotPasswordLimiter,
  resendVerificationLimiter,
  generalAuthLimiter,
  uploadPresignLimiter,
  changePasswordLimiter,
  accountExportLimiter,
  accountDeleteLimiter,
};
