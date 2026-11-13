const { z } = require("zod");
const { plainTextString } = require("../utils/plainText");

/**
 * Strict password rule:
 * - At least 8 characters
 * - At least 1 uppercase letter
 * - At least 1 lowercase letter
 * - At least 1 number
 * - At least 1 special character
 */
const passwordSchema = z
  .string({ error: "Password is required" })
  .min(8, "Password must be at least 8 characters long")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(
    /[^A-Za-z0-9]/,
    "Password must contain at least one special character (!@#$%^&* etc.)"
  );

const newPasswordSchema = z
  .string({ error: "New password is required" })
  .min(8, "Password must be at least 8 characters long")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(
    /[^A-Za-z0-9]/,
    "Password must contain at least one special character (!@#$%^&* etc.)"
  );

/**
 * Email rule:
 * - Trim whitespace
 * - Convert to lowercase
 * - Must be valid email syntax
 */
const emailSchema = z
  .string({ error: "Email is required" })
  .trim()
  .toLowerCase()
  .email("Please provide a valid email address");

const signupSchema = z.object({
  firstName: plainTextString({
    max: 100,
    required: true,
    error: "First name is required",
  }),
  lastName: plainTextString({ max: 100 })
    .optional()
    .nullable()
    .or(z.literal("")),
  email: emailSchema,
  password: passwordSchema,
  referralCode: z
    .string()
    .trim()
    .max(50)
    .optional()
    .nullable()
    .or(z.literal("")),
});

const loginSchema = z.object({
  email: emailSchema,
  password: z
    .string({ error: "Password is required" })
    .min(1, "Password is required"),
});

const forgotPasswordSchema = z.object({
  email: emailSchema,
});

const resetPasswordSchema = z.object({
  token: z
    .string({ error: "Reset token is required" })
    .trim()
    .min(1, "Reset token is required"),
  newPassword: newPasswordSchema,
});

const validateResetTokenSchema = z.object({
  token: z
    .string({ error: "Reset token is required" })
    .trim()
    .min(1, "Reset token is required"),
});

const requestVerificationSchema = z.object({
  email: emailSchema,
});

const verifyEmailSchema = z.object({
  token: z
    .string({ error: "Verification token is required" })
    .trim()
    .min(1, "Verification token is required"),
});

const oauthExchangeSchema = z.object({
  code: z
    .string({ error: "Code is required" })
    .trim()
    .min(1, "Code is required"),
});

module.exports = {
  passwordSchema,
  newPasswordSchema,
  emailSchema,
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  validateResetTokenSchema,
  requestVerificationSchema,
  verifyEmailSchema,
  oauthExchangeSchema,
};
