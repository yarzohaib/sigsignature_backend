const express = require("express");

const authController = require("../controllers/auth.controller");
const oauthController = require("../controllers/oauth.controller");
const { authenticate } = require("../middleware/auth.middleware");
const { validate } = require("../middleware/validate.middleware");
const {
  generalAuthLimiter,
  loginLimiter,
  signupLimiter,
  forgotPasswordLimiter,
  resendVerificationLimiter,
} = require("../middleware/rateLimiter.middleware");
const {
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  validateResetTokenSchema,
  requestVerificationSchema,
  verifyEmailSchema,
  oauthExchangeSchema,
} = require("../validators/auth.validator");

const router = express.Router();

// Apply general rate limiter across all auth routes (except POST /login which has its own dedicated loginLimiter)
router.use((req, res, next) => {
  if (req.path === "/login" && req.method === "POST") {
    return next();
  }
  return generalAuthLimiter(req, res, next);
});

// OAuth Routes
router.get("/google", oauthController.googleAuth);
router.get("/google/callback", oauthController.googleCallback);

router.get("/github", oauthController.githubAuth);
router.get("/github/callback", oauthController.githubCallback);

router.post(
  "/oauth/exchange",
  validate(oauthExchangeSchema),
  oauthController.oauthExchange
);

// Account creation & authentication
router.post("/signup", signupLimiter, validate(signupSchema), authController.signup);
router.post("/login", validate(loginSchema), loginLimiter, authController.login);
router.post("/refresh", authController.refresh);
router.post("/logout", authController.logout);

// Protected session management
router.get("/me", authenticate, authController.me);
router.post("/logout-all", authenticate, authController.logoutAll);
router.get("/sessions", authenticate, authController.sessions);
router.post("/sessions/revoke-others", authenticate, authController.revokeOtherSessions);
router.delete("/sessions/:id", authenticate, authController.revokeSession);

// Password recovery & email verification with abuse/cost protection
router.post(
  "/forgot-password",
  validate(forgotPasswordSchema),
  forgotPasswordLimiter,
  authController.forgotPassword
);

router.post(
  "/validate-reset-token",
  validate(validateResetTokenSchema),
  authController.validateResetToken
);

router.post(
  "/reset-password",
  validate(resetPasswordSchema),
  authController.resetPassword
);

router.post(
  "/request-verification",
  validate(requestVerificationSchema),
  resendVerificationLimiter,
  authController.requestVerification
);

router.post(
  "/verify-email",
  validate(verifyEmailSchema),
  authController.verifyEmail
);

module.exports = router;