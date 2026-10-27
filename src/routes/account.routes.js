const express = require("express");
const accountController = require("../controllers/account.controller");
const { authenticate } = require("../middleware/auth.middleware");
const { validate } = require("../middleware/validate.middleware");
const {
  createRateLimiter,
  changePasswordLimiter,
  accountExportLimiter,
  accountDeleteLimiter,
} = require("../middleware/rateLimiter.middleware");
const {
  updateProfileSchema,
  updateSettingsSchema,
  changePasswordSchema,
  deleteAccountSchema,
} = require("../validators/account.validator");

const router = express.Router();

// All account routes require authentication
router.use(authenticate);

// Write rate limiter: 60 write requests per 15 minutes per user
const writeRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: "Too many write requests. Please try again later.",
  keyGenerator: (req) => req.user?.id || req.user?.sub || req.ip,
});

/**
 * @route   GET /api/v1/account
 * @desc    Get account details (user, hasPassword, providers, settings, usage)
 * @access  Private
 */
router.get("/", accountController.getAccount);

/**
 * @route   PATCH /api/v1/account
 * @desc    Update user profile (firstName, lastName, companyName)
 * @access  Private
 */
router.patch(
  "/",
  writeRateLimiter,
  validate(updateProfileSchema),
  accountController.updateProfile
);

/**
 * @route   PATCH /api/v1/account/settings
 * @desc    Upsert user signature and notification settings
 * @access  Private
 */
router.patch(
  "/settings",
  writeRateLimiter,
  validate(updateSettingsSchema),
  accountController.updateSettings
);

/**
 * @route   POST /api/v1/account/waitlist
 * @desc    Join premium waitlist (idempotent)
 * @access  Private
 */
router.post(
  "/waitlist",
  writeRateLimiter,
  accountController.joinWaitlist
);

/**
 * @route   POST /api/v1/account/onboarding-seen
 * @desc    Mark onboarding modal as seen (idempotent)
 * @access  Private
 */
router.post(
  "/onboarding-seen",
  writeRateLimiter,
  accountController.markOnboardingSeen
);

/**
 * @route   POST /api/v1/account/password
 * @desc    Change password, revoke other sessions, and send email alert
 * @access  Private (strict rate limit like login)
 */
router.post(
  "/password",
  changePasswordLimiter,
  validate(changePasswordSchema),
  accountController.changePassword
);

/**
 * @route   GET /api/v1/account/export
 * @desc    Export account data as JSON attachment without secrets
 * @access  Private (rate limit: 3 per hour)
 */
router.get(
  "/export",
  accountExportLimiter,
  accountController.exportAccount
);

/**
 * @route   DELETE /api/v1/account
 * @desc    Permanently delete user and all owned data
 * @access  Private (rate limit: 3 per hour)
 */
router.delete(
  "/",
  accountDeleteLimiter,
  validate(deleteAccountSchema),
  accountController.deleteAccount
);

module.exports = router;
