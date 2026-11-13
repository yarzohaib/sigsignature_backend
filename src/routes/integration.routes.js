const express = require("express");
const integrationController = require("../controllers/integration.controller");
const { authenticate } = require("../middleware/auth.middleware");
const { validate } = require("../middleware/validate.middleware");
const { createRateLimiter, getClientIp } = require("../middleware/rateLimiter.middleware");
const { connectGmailSchema, pushGmailSchema } = require("../validators/integration.validator");

const router = express.Router();

const perUserKey = (req) => {
  const userId = req.user?.id || req.user?.sub;
  return userId ? `gmail:user:${userId}` : `gmail:ip:${getClientIp(req)}`;
};

const connectLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: "Too many Gmail connection attempts. Please try again later.",
  code: "GMAIL_CONNECT_RATE_LIMITED",
  keyGenerator: (req) => `connect:${perUserKey(req)}`,
});

const pushLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: "Too many Gmail updates. You can push up to 30 times per hour.",
  code: "GMAIL_PUSH_RATE_LIMITED",
  keyGenerator: (req) => `push:${perUserKey(req)}`,
});

const callbackLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: "Too many requests. Please try again later.",
  code: "GMAIL_CALLBACK_RATE_LIMITED",
  keyGenerator: (req) => `callback:ip:${getClientIp(req)}`,
});

/**
 * Google redirects the browser here without our auth header, so it is public.
 * It is protected by the signed, short lived state value created in /connect.
 */
router.get("/gmail/callback", callbackLimiter, integrationController.gmailCallback);

// Everything below requires a signed in user
router.use(authenticate);

router.get("/gmail", integrationController.gmailStatus);
router.post("/gmail/connect", connectLimiter, validate(connectGmailSchema), integrationController.gmailConnect);
router.post("/gmail/push", pushLimiter, validate(pushGmailSchema), integrationController.gmailPush);
router.delete("/gmail", integrationController.gmailDisconnect);

module.exports = router;
