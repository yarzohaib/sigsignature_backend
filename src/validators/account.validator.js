const { z } = require("zod");
const { plainTextString } = require("../utils/plainText");
const { ALLOWED_FONT_FAMILIES } = require("./signature.validator");

/**
 * Validator for updating user profile.
 * - firstName: 2 to 20, trimmed, required if sent, plain text only
 * - lastName: 0 to 20, nullable, plain text only
 * - companyName: 0 to 100, nullable, plain text only
 * - email: ignored silently if sent
 * - strips unknown keys
 */
const updateProfileSchema = z
  .object({
    firstName: plainTextString({
      min: 2,
      max: 20,
      required: true,
      error: "First name must be between 2 and 20 characters",
    }).optional(),
    lastName: plainTextString({
      max: 20,
      error: "Last name cannot exceed 20 characters",
    })
      .nullable()
      .optional(),
    companyName: plainTextString({ max: 100 }).nullable().optional(),
    avatarUrl: z
      .string({ error: "Avatar URL must be a string" })
      .trim()
      .refine(
        (val) => val === "" || (val.startsWith("https://") && val.length <= 2048),
        { error: "Avatar URL must be empty or an HTTPS URL" }
      )
      .nullable()
      .optional(),
    email: z.any().optional(), // Ignored silently
  })
  .strip()
  .refine(
    (body) => {
      return (
        body.firstName !== undefined ||
        body.lastName !== undefined ||
        body.companyName !== undefined ||
        body.avatarUrl !== undefined
      );
    },
    {
      error: "At least one field (firstName, lastName, companyName, or avatarUrl) must be provided for update",
    }
  );

/**
 * Validator for updating account settings.
 * - defaultTemplateId: null or slug string max 64, safe characters only
 * - defaultExportFormat: "html" or "plain"
 * - signatureFont: strictly from ALLOWED_FONT_FAMILIES enum (no quotes, semicolons, or free text)
 * - brandColor: strict 6-digit hex code (^#[0-9a-fA-F]{6}$)
 * - includePhoto: boolean
 * - notifyProductUpdates: boolean
 * - notifyTips: boolean
 * - strips unknown keys
 */
const updateSettingsSchema = z
  .object({
    defaultTemplateId: z
      .string({ error: "Default template ID must be a string" })
      .trim()
      .max(64, { error: "Default template ID cannot exceed 64 characters" })
      .regex(/^[a-zA-Z0-9_-]+$/, {
        error: "Default template ID may only contain letters, numbers, hyphens, and underscores",
      })
      .nullable()
      .optional(),
    defaultExportFormat: z
      .enum(["html", "plain"], {
        error: "Default export format must be 'html' or 'plain'",
      })
      .optional(),
    signatureFont: z
      .enum(ALLOWED_FONT_FAMILIES, {
        error: `Signature font must be one of: ${ALLOWED_FONT_FAMILIES.join(", ")}`,
      })
      .optional(),
    brandColor: z
      .string({ error: "Brand color must be a string" })
      .trim()
      .regex(/^#[0-9a-fA-F]{6}$/, {
        error: "Brand color must be a valid 6-digit hex color code (#RRGGBB)",
      })
      .optional(),
    includePhoto: z
      .boolean({ error: "includePhoto must be a boolean" })
      .optional(),
    notifyProductUpdates: z
      .boolean({ error: "notifyProductUpdates must be a boolean" })
      .optional(),
    notifyTips: z
      .boolean({ error: "notifyTips must be a boolean" })
      .optional(),
  })
  .strip()
  .refine(
    (body) => {
      return (
        body.defaultTemplateId !== undefined ||
        body.defaultExportFormat !== undefined ||
        body.signatureFont !== undefined ||
        body.brandColor !== undefined ||
        body.includePhoto !== undefined ||
        body.notifyProductUpdates !== undefined ||
        body.notifyTips !== undefined
      );
    },
    {
      error: "At least one settings field must be provided for update",
    }
  );

/**
 * Validator for password change.
 * - currentPassword: string, required
 * - newPassword: adheres to signup password rules (min 8, 1 uppercase, 1 lowercase, 1 number, 1 special char)
 * - must differ from currentPassword
 */
const changePasswordSchema = z
  .object({
    currentPassword: z
      .string({ error: "Current password is required" })
      .min(1, { error: "Current password is required" }),
    newPassword: z
      .string({ error: "New password is required" })
      .min(8, { error: "Password must be at least 8 characters long" })
      .regex(/[A-Z]/, { error: "Password must contain at least one uppercase letter" })
      .regex(/[a-z]/, { error: "Password must contain at least one lowercase letter" })
      .regex(/[0-9]/, { error: "Password must contain at least one number" })
      .regex(
        /[^A-Za-z0-9]/,
        { error: "Password must contain at least one special character (!@#$%^&* etc.)" }
      ),
  })
  .strip()
  .refine((data) => data.currentPassword !== data.newPassword, {
    message: "New password must differ from the current password",
    path: ["newPassword"],
  });

/**
 * Validator for account deletion.
 * - password: string optional (required if account has password)
 * - confirm: string optional (must equal 'DELETE' if account is OAuth only)
 */
const deleteAccountSchema = z
  .object({
    password: z.string().optional(),
    confirm: z.string().optional(),
  })
  .strip();

module.exports = {
  updateProfileSchema,
  updateSettingsSchema,
  changePasswordSchema,
  deleteAccountSchema,
};
