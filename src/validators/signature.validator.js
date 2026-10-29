const { z } = require("zod");
const { plainTextString } = require("../utils/plainText");

/**
 * Validates that an image URL is either:
 * 1. A relative path starting with "/" and containing no "//" or ".."
 * 2. An HTTPS URL starting with process.env.S3_PUBLIC_BASE_URL
 * Reject data: URLs and anything else.
 */
const isValidImageUrl = (val) => {
  if (typeof val !== "string") return false;
  const trimmed = val.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith("data:")) return false;

  // Relative path starting with "/" and containing no "//" or ".."
  if (trimmed.startsWith("/")) {
    if (trimmed.includes("//") || trimmed.includes("..")) {
      return false;
    }
    return true;
  }

  // HTTPS URL starting with process.env.S3_PUBLIC_BASE_URL
  const s3Base = (
    process.env.S3_PUBLIC_BASE_URL ||
    "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com"
  ).replace(/\/+$/, "");

  if (trimmed.startsWith("https://") && trimmed.startsWith(s3Base)) {
    return true;
  }

  return false;
};

/**
 * Profile photo hosts of sign in providers (Google, GitHub). An avatar from one of these is
 * accepted on save and then copied into our own S3 bucket by the service layer, so stored
 * signatures never depend on a third party link.
 */
const TRUSTED_AVATAR_HOST_PATTERNS = [
  /^[a-z0-9-]+\.googleusercontent\.com$/i,
  /^avatars\.githubusercontent\.com$/i,
];

const isTrustedProviderAvatarUrl = (val) => {
  if (typeof val !== "string") return false;
  const trimmed = val.trim();
  if (!trimmed || trimmed.length > 600) return false;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "https:") return false;
    if (url.username || url.password) return false;
    return TRUSTED_AVATAR_HOST_PATTERNS.some((re) => re.test(url.hostname));
  } catch {
    return false;
  }
};

/** Avatar: relative path, our S3 bucket, or a trusted sign in provider photo. */
const isValidAvatarUrl = (val) => isValidImageUrl(val) || isTrustedProviderAvatarUrl(val);

/**
 * Validates that an S3 image URL is strictly an HTTPS URL
 * starting with process.env.S3_PUBLIC_BASE_URL.
 * Relative paths, data: URLs, and other origins are rejected.
 */
const isValidS3Url = (val) => {
  if (typeof val !== "string") return false;
  const trimmed = val.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith("data:")) return false;

  const s3Base = (
    process.env.S3_PUBLIC_BASE_URL ||
    "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com"
  ).replace(/\/+$/, "");

  return trimmed.startsWith("https://") && trimmed.startsWith(s3Base);
};

/**
 * Validates optional HTTP/HTTPS URL (max 300 chars, empty string or undefined allowed).
 */
const isValidHttpUrl = (val) => {
  if (val === "" || val === undefined || val === null) return true;
  if (typeof val !== "string") return false;
  const trimmed = val.trim();
  if (!trimmed) return true;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
};

/**
 * Validates social URL: must be empty string, a social handle (e.g. @handle), or a valid HTTP/HTTPS URL (max 300 chars)
 */
const isValidSocialUrl = (val) => {
  if (val === "" || val === undefined || val === null) return true;
  if (typeof val !== "string") return false;
  const trimmed = val.trim();
  if (!trimmed) return true;
  if (/^@?[\w.-]+$/.test(trimmed)) return true;
  return isValidHttpUrl(val);
};

const ALLOWED_FONT_FAMILIES = [
  "Arial",
  "Georgia",
  "Verdana",
  "Trebuchet MS",
  "Tahoma",
  "Inter",
  "Roboto",
  "DM Sans",
  "Montserrat",
  "Commissioner",
];

const ALLOWED_LAYOUTS = [
  "two-column",
  "horizontal",
  "compact",
  "single",
  "corporate-card",
];

const ALLOWED_SOCIAL_ICONS_STYLES = [
  "filled",
  "outline",
  "circle",
  "minimal",
];

const ALLOWED_THEMES = ["corporate", "minimal", "modern", "dark"];
const ALLOWED_SHAPES = ["rounded", "square", "pill"];
const ALLOWED_BUTTON_STYLES = ["solid", "outline"];
const ALLOWED_ALIGNS = ["left", "center", "right"];
const ALLOWED_SIZES = ["sm", "md", "lg"];
const ALLOWED_COLUMNS = ["left", "right", "full"];
const ALLOWED_ORIENTATIONS = ["horizontal", "vertical"];

/**
 * Helper to validate enum fields with descriptive error messages
 * that include the received value and the allowed options.
 */
function friendlyEnum(name, allowedValues, isOptional = false) {
  return z
    .any()
    .superRefine((val, ctx) => {
      if (val === undefined) {
        if (!isOptional) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `${name} is required`,
          });
        }
        return;
      }
      const checkVal = typeof val === "string" ? val.trim() : val;
      if (!allowedValues.includes(checkVal)) {
        const displayVal =
          typeof val === "object" && val !== null
            ? JSON.stringify(val)
            : String(val);
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Invalid ${name} "${displayVal}". Allowed values: ${allowedValues.join(", ")}`,
        });
      }
    })
    .transform((val) => (typeof val === "string" ? val.trim() : val));
}

const socialsSchema = z
  .object({
    linkedin: z
      .string()
      .trim()
      .max(300, { error: "LinkedIn URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "LinkedIn URL must be empty or a valid HTTP/HTTPS URL",
      })
      .default(""),
    twitter: z
      .string()
      .trim()
      .max(300, { error: "Twitter URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "Twitter URL must be empty or a valid HTTP/HTTPS URL",
      })
      .default(""),
    facebook: z
      .string()
      .trim()
      .max(300, { error: "Facebook URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "Facebook URL must be empty or a valid HTTP/HTTPS URL",
      })
      .default(""),
    instagram: z
      .string()
      .trim()
      .max(300, { error: "Instagram URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "Instagram URL must be empty or a valid HTTP/HTTPS URL",
      })
      .optional()
      .default(""),
  })
  .strip()
  .default({});

const updateSocialsSchema = z
  .object({
    linkedin: z
      .string()
      .trim()
      .max(300, { error: "LinkedIn URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "LinkedIn URL must be empty or a valid HTTP/HTTPS URL",
      })
      .optional(),
    twitter: z
      .string()
      .trim()
      .max(300, { error: "Twitter URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "Twitter URL must be empty or a valid HTTP/HTTPS URL",
      })
      .optional(),
    facebook: z
      .string()
      .trim()
      .max(300, { error: "Facebook URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "Facebook URL must be empty or a valid HTTP/HTTPS URL",
      })
      .optional(),
    instagram: z
      .string()
      .trim()
      .max(300, { error: "Instagram URL cannot exceed 300 characters" })
      .refine(isValidSocialUrl, {
        error: "Instagram URL must be empty or a valid HTTP/HTTPS URL",
      })
      .optional(),
  })
  .strip()
  .optional();

const optionalSchema = z
  .object({
    address: plainTextString({ max: 250 }).optional().default(""),
    tagline: plainTextString({ max: 150 }).optional().default(""),
    disclaimer: plainTextString({ max: 1000 }).optional().default(""),
  })
  .strip()
  .default({});

const updateOptionalSchema = z
  .object({
    address: plainTextString({ max: 250 }).optional(),
    tagline: plainTextString({ max: 150 }).optional(),
    disclaimer: plainTextString({ max: 1000 }).optional(),
  })
  .strip()
  .optional();

/**
 * Optional design configuration (Design Studio).
 * Rejects premium themes (luxury, glass, neon) and shapes (glass, blob).
 */
const designSchema = z
  .object({
    theme: friendlyEnum("theme", ALLOWED_THEMES),
    shape: friendlyEnum("shape", ALLOWED_SHAPES),
    buttonStyle: friendlyEnum("buttonStyle", ALLOWED_BUTTON_STYLES),
  })
  .strip();

const updateDesignSchema = z
  .object({
    theme: friendlyEnum("theme", ALLOWED_THEMES, true).optional(),
    shape: friendlyEnum("shape", ALLOWED_SHAPES, true).optional(),
    buttonStyle: friendlyEnum("buttonStyle", ALLOWED_BUTTON_STYLES, true).optional(),
  })
  .strip();

/**
 * Discriminated union of extra items (maximum 20 items in extras array).
 */
const extraTextSchema = z
  .object({
    type: z.literal("text"),
    id: z
      .string({ error: "Item ID is required" })
      .trim()
      .min(1, { error: "Item ID cannot be empty" })
      .max(40, { error: "Item ID cannot exceed 40 characters" }),
    text: plainTextString({ max: 300, required: true }),
    align: friendlyEnum("align", ALLOWED_ALIGNS),
    size: friendlyEnum("size", ALLOWED_SIZES),
    bold: z.boolean({ error: "Bold must be a boolean" }),
    width: z
      .number({ error: "Width must be a number" })
      .int({ error: "Width must be an integer" })
      .min(20, { error: "Width must be between 20 and 600" })
      .max(600, { error: "Width must be between 20 and 600" })
      .optional(),
    column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
  })
  .strip();

const extraImageSchema = z
  .object({
    type: z.literal("image"),
    id: z
      .string({ error: "Item ID is required" })
      .trim()
      .min(1, { error: "Item ID cannot be empty" })
      .max(40, { error: "Item ID cannot exceed 40 characters" }),
    url: z
      .string({ error: "Image URL is required" })
      .trim()
      .refine(isValidS3Url, {
        error:
          "Image URL must be an HTTPS URL hosted on authorized storage",
      }),
    width: z
      .number({ error: "Width must be a number" })
      .int({ error: "Width must be an integer" })
      .min(20, { error: "Width must be between 20 and 600" })
      .max(600, { error: "Width must be between 20 and 600" }),
    align: friendlyEnum("align", ALLOWED_ALIGNS),
    linkUrl: z
      .string()
      .trim()
      .max(300, { error: "Link URL cannot exceed 300 characters" })
      .refine(isValidHttpUrl, {
        error: "Link URL must be a valid HTTP or HTTPS URL",
      })
      .optional(),
    column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
  })
  .strip();

const extraDividerSchema = z
  .object({
    type: z.literal("divider"),
    id: z
      .string({ error: "Item ID is required" })
      .trim()
      .min(1, { error: "Item ID cannot be empty" })
      .max(40, { error: "Item ID cannot exceed 40 characters" }),
    width: z
      .number({ error: "Width must be a number" })
      .int({ error: "Width must be an integer" })
      .min(20, { error: "Width must be between 20 and 600" })
      .max(600, { error: "Width must be between 20 and 600" })
      .optional(),
    align: friendlyEnum("align", ALLOWED_ALIGNS, true).optional(),
    thickness: z
      .number({ error: "Thickness must be a number" })
      .int({ error: "Thickness must be an integer" })
      .min(1, { error: "Thickness must be between 1 and 20" })
      .max(20, { error: "Thickness must be between 1 and 20" })
      .optional(),
    orientation: friendlyEnum("orientation", ALLOWED_ORIENTATIONS, true).optional(),
    column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
  })
  .strip();

const extraCtaSchema = z
  .object({
    type: z.literal("cta"),
    id: z
      .string({ error: "Item ID is required" })
      .trim()
      .min(1, { error: "Item ID cannot be empty" })
      .max(40, { error: "Item ID cannot exceed 40 characters" }),
    label: plainTextString({ max: 40, required: true }),
    url: z
      .string({ error: "URL is required" })
      .trim()
      .max(300, { error: "URL cannot exceed 300 characters" })
      .refine(
        (val) => {
          if (!val) return false;
          try {
            const parsed = new URL(val);
            return (
              parsed.protocol === "http:" || parsed.protocol === "https:"
            );
          } catch {
            return false;
          }
        },
        { error: "URL must be a valid HTTP or HTTPS URL" }
      ),
    align: friendlyEnum("align", ALLOWED_ALIGNS),
    width: z
      .number({ error: "Width must be a number" })
      .int({ error: "Width must be an integer" })
      .min(20, { error: "Width must be between 20 and 600" })
      .max(600, { error: "Width must be between 20 and 600" })
      .optional(),
    column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
  })
  .strip();

const extraBannerSchema = z
  .object({
    type: z.literal("banner"),
    id: z
      .string({ error: "Item ID is required" })
      .trim()
      .min(1, { error: "Item ID cannot be empty" })
      .max(40, { error: "Item ID cannot exceed 40 characters" }),
    imageUrl: z
      .string({ error: "Banner image URL is required" })
      .trim()
      .refine(isValidS3Url, {
        error:
          "Banner image URL must be an HTTPS URL hosted on authorized storage",
      }),
    linkUrl: z
      .string()
      .trim()
      .max(300, { error: "Link URL cannot exceed 300 characters" })
      .refine(isValidHttpUrl, {
        error: "Link URL must be a valid HTTP or HTTPS URL",
      })
      .optional(),
    column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
  })
  .strip();

const extraItemSchema = z.discriminatedUnion(
  "type",
  [
    extraTextSchema,
    extraImageSchema,
    extraDividerSchema,
    extraCtaSchema,
    extraBannerSchema,
  ],
  {
    error:
      "Extra item type must be one of 'text', 'image', 'divider', 'cta', or 'banner'",
  }
);

const extrasSchema = z
  .array(extraItemSchema, {
    error: "Extras must be an array",
  })
  .max(20, { error: "Extras cannot exceed 20 items" })
  .optional();

const freeTextSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("text"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
    text: plainTextString({ max: 1000 }).default(""),
    size: friendlyEnum("size", ALLOWED_SIZES, true).default("md"),
    bold: z.boolean().default(false),
    align: friendlyEnum("align", ALLOWED_ALIGNS, true).default("left"),
    bind: friendlyEnum("bind", ["name", "jobTitle", "email", "phone", "company", "website"], true).optional(),
    icon: z.enum(["phone", "email", "website", "address"]).nullable().optional(),
  })
  .passthrough();

const freeImageSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("image"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
    url: z.string().max(2000).default(""),
    linkUrl: z.string().max(2000).optional(),
    bind: friendlyEnum("bind", ["photo"], true).optional(),
  })
  .passthrough();

const freeLogoSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("logo"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
    url: z.string().max(2000).default(""),
    linkUrl: z.string().max(2000).optional(),
  })
  .passthrough();

const freeBannerSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("banner"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
    url: z.string().max(2000).default(""),
    linkUrl: z.string().max(2000).optional(),
  })
  .passthrough();

const freeDividerSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("divider"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
    orientation: friendlyEnum("orientation", ALLOWED_ORIENTATIONS, true).default("horizontal"),
    thickness: z.number().min(1).max(50).default(1),
  })
  .passthrough();

const freeCtaSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("cta"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
    label: plainTextString({ max: 200 }).default("Button"),
    url: z.string().max(2000).default("#"),
  })
  .passthrough();

const freeSocialSchema = z
  .object({
    id: z.string().min(1).max(64),
    type: z.literal("social"),
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number(),
    locked: z.boolean().optional(),
  })
  .passthrough();

const freeElementSchema = z.discriminatedUnion("type", [
  freeTextSchema,
  freeImageSchema,
  freeLogoSchema,
  freeBannerSchema,
  freeDividerSchema,
  freeCtaSchema,
  freeSocialSchema,
]);

const freeElementsSchema = z.array(freeElementSchema).max(50).optional();

const canvasSchema = z
  .object({
    width: z.number().int().min(100).max(1200).default(600),
    height: z.number().int().min(50).max(2000).default(200),
  })
  .passthrough()
  .optional();

const themeColorSchema = z
  .string({ error: "Theme color must be a string" })
  .trim()
  .regex(/^#[0-9a-fA-F]{6}$/, {
    error: "Theme color must be a valid hex color code matching #RRGGBB",
  });

/**
 * Signature data schema with defaults for POST /api/v1/signatures.
 * Missing styling fields default to brand and template defaults.
 */
const signatureDataSchema = z
  .object({
    fullName: plainTextString({ max: 100 }).default(""),
    jobTitle: plainTextString({ max: 100 }).default(""),
    companyName: plainTextString({ max: 100 }).default(""),
    email: plainTextString({ max: 254 }).default(""),
    phone: plainTextString({ max: 40 }).default(""),
    website: plainTextString({ max: 200 }).default(""),
    avatarUrl: z
      .string()
      .trim()
      .refine((val) => val === "" || isValidAvatarUrl(val), {
        error:
          "Avatar URL must be empty, a relative path starting with '/', a Google or GitHub profile photo, or an HTTPS URL hosted on authorized storage",
      })
      .optional()
      .default(""),
    companyLogoUrl: z
      .string()
      .trim()
      .refine((val) => val === "" || isValidImageUrl(val), {
        error:
          "Company logo URL must be empty, a relative path starting with '/', or an HTTPS URL hosted on authorized storage",
      })
      .optional()
      .default(""),
    themeColor: themeColorSchema.default("#2563eb"),
    fontFamily: friendlyEnum("fontFamily", ALLOWED_FONT_FAMILIES).default("Arial"),
    layout: friendlyEnum("layout", ALLOWED_LAYOUTS).default("two-column"),
    socialIconsStyle: friendlyEnum("socialIconsStyle", ALLOWED_SOCIAL_ICONS_STYLES).default("filled"),
    design: designSchema.optional(),
    extras: extrasSchema,
    socials: socialsSchema,
    optional: optionalSchema,
    address: plainTextString({ max: 250 }).optional(),
    tagline: plainTextString({ max: 150 }).optional(),
    disclaimer: plainTextString({ max: 1000 }).optional(),
    canvas: canvasSchema,
    elements: freeElementsSchema,
  })
  .passthrough();

/**
 * Partial signature data schema for PATCH /api/v1/signatures/:id.
 * Fields are optional and do NOT have defaults, preventing silent overwrite of existing values.
 */
const updateSignatureDataSchema = z
  .object({
    fullName: plainTextString({ max: 100 }).optional(),
    jobTitle: plainTextString({ max: 100 }).optional(),
    companyName: plainTextString({ max: 100 }).optional(),
    email: plainTextString({ max: 254 }).optional(),
    phone: plainTextString({ max: 40 }).optional(),
    website: plainTextString({ max: 200 }).optional(),
    avatarUrl: z
      .string()
      .trim()
      .refine((val) => val === "" || isValidAvatarUrl(val), {
        error:
          "Avatar URL must be empty, a relative path starting with '/', a Google or GitHub profile photo, or an HTTPS URL hosted on authorized storage",
      })
      .optional(),
    companyLogoUrl: z
      .string()
      .trim()
      .refine((val) => val === "" || isValidImageUrl(val), {
        error:
          "Company logo URL must be empty, a relative path starting with '/', or an HTTPS URL hosted on authorized storage",
      })
      .optional(),
    themeColor: themeColorSchema.optional(),
    fontFamily: friendlyEnum("fontFamily", ALLOWED_FONT_FAMILIES, true).optional(),
    layout: friendlyEnum("layout", ALLOWED_LAYOUTS, true).optional(),
    socialIconsStyle: friendlyEnum("socialIconsStyle", ALLOWED_SOCIAL_ICONS_STYLES, true).optional(),
    design: updateDesignSchema.optional(),
    extras: extrasSchema,
    socials: updateSocialsSchema,
    optional: updateOptionalSchema,
    address: plainTextString({ max: 250 }).optional(),
    tagline: plainTextString({ max: 150 }).optional(),
    disclaimer: plainTextString({ max: 1000 }).optional(),
    canvas: canvasSchema,
    elements: freeElementsSchema,
  })
  .passthrough();

const createSignatureSchema = z
  .object({
    name: plainTextString({ max: 100, required: true }),
    templateId: z
      .string({ error: "Template ID is required" })
      .trim()
      .min(1, { error: "Template ID cannot be empty" })
      .max(64, { error: "Template ID cannot exceed 64 characters" })
      .regex(/^[a-z0-9-]+$/, {
        error:
          "Template ID must contain only lowercase letters, digits, and dashes",
      }),
    templateVersion: z
      .number({ error: "Template version must be a number" })
      .int({ error: "Template version must be an integer" })
      .min(1, { error: "Template version must be between 1 and 1000" })
      .max(1000, { error: "Template version must be between 1 and 1000" })
      .default(1),
    data: z.preprocess(
      (val) => (val === undefined ? {} : val),
      signatureDataSchema
    ),
  })
  .strip()
  .refine(
    (body) => Buffer.byteLength(JSON.stringify(body.data), "utf8") <= 65536,
    {
      error: "Signature data payload size cannot exceed 64 KB",
      path: ["data"],
    }
  );

const updateSignatureSchema = z
  .object({
    name: plainTextString({ max: 100, required: true }).optional(),
    templateId: z
      .string({ error: "Template ID must be a string" })
      .trim()
      .min(1, { error: "Template ID cannot be empty" })
      .max(64, { error: "Template ID cannot exceed 64 characters" })
      .regex(/^[a-z0-9-]+$/, {
        error:
          "Template ID must contain only lowercase letters, digits, and dashes",
      })
      .optional(),
    templateVersion: z
      .number({ error: "Template version must be a number" })
      .int({ error: "Template version must be an integer" })
      .min(1, { error: "Template version must be between 1 and 1000" })
      .max(1000, { error: "Template version must be between 1 and 1000" })
      .optional(),
    data: updateSignatureDataSchema.optional(),
  })
  .strip()
  .refine(
    (body) => {
      return (
        body.name !== undefined ||
        body.templateId !== undefined ||
        body.templateVersion !== undefined ||
        body.data !== undefined
      );
    },
    {
      error:
        "At least one field (name, templateId, templateVersion, or data) must be provided for update",
    }
  )
  .refine(
    (body) => {
      if (!body.data) return true;
      return Buffer.byteLength(JSON.stringify(body.data), "utf8") <= 65536;
    },
    {
      error: "Signature data payload size cannot exceed 64 KB",
      path: ["data"],
    }
  );

const signatureIdParamSchema = z
  .object({
    id: z
      .string({ error: "Signature ID is required" })
      .trim()
      .min(1, { error: "Signature ID cannot be empty" })
      .max(64, { error: "Signature ID cannot exceed 64 characters" }),
  })
  .strip();

module.exports = {
  createSignatureSchema,
  updateSignatureSchema,
  signatureIdParamSchema,
  signatureDataSchema,
  updateSignatureDataSchema,
  isValidImageUrl,
  isValidAvatarUrl,
  isTrustedProviderAvatarUrl,
  isValidS3Url,
  ALLOWED_FONT_FAMILIES,
  ALLOWED_LAYOUTS,
  ALLOWED_SOCIAL_ICONS_STYLES,
};


// const { z } = require("zod");
// const { plainTextString } = require("../utils/plainText");

// /**
//  * Validates that an image URL is either:
//  * 1. A relative path starting with "/" and containing no "//" or ".."
//  * 2. An HTTPS URL starting with process.env.S3_PUBLIC_BASE_URL
//  * Reject data: URLs and anything else.
//  */
// const isValidImageUrl = (val) => {
//   if (typeof val !== "string") return false;
//   const trimmed = val.trim();
//   if (!trimmed) return false;
//   if (trimmed.startsWith("data:")) return false;

//   // Relative path starting with "/" and containing no "//" or ".."
//   if (trimmed.startsWith("/")) {
//     if (trimmed.includes("//") || trimmed.includes("..")) {
//       return false;
//     }
//     return true;
//   }

//   // HTTPS URL starting with process.env.S3_PUBLIC_BASE_URL
//   const s3Base = (
//     process.env.S3_PUBLIC_BASE_URL ||
//     "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com"
//   ).replace(/\/+$/, "");

//   if (trimmed.startsWith("https://") && trimmed.startsWith(s3Base)) {
//     return true;
//   }

//   return false;
// };

// /**
//  * Validates that an S3 image URL is strictly an HTTPS URL
//  * starting with process.env.S3_PUBLIC_BASE_URL.
//  * Relative paths, data: URLs, and other origins are rejected.
//  */
// const isValidS3Url = (val) => {
//   if (typeof val !== "string") return false;
//   const trimmed = val.trim();
//   if (!trimmed) return false;
//   if (trimmed.startsWith("data:")) return false;

//   const s3Base = (
//     process.env.S3_PUBLIC_BASE_URL ||
//     "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com"
//   ).replace(/\/+$/, "");

//   return trimmed.startsWith("https://") && trimmed.startsWith(s3Base);
// };

// /**
//  * Validates optional HTTP/HTTPS URL (max 300 chars, empty string or undefined allowed).
//  */
// const isValidHttpUrl = (val) => {
//   if (val === "" || val === undefined || val === null) return true;
//   if (typeof val !== "string") return false;
//   const trimmed = val.trim();
//   if (!trimmed) return true;
//   try {
//     const parsed = new URL(trimmed);
//     return parsed.protocol === "http:" || parsed.protocol === "https:";
//   } catch {
//     return false;
//   }
// };

// /**
//  * Validates social URL: must be empty string, a social handle (e.g. @handle), or a valid HTTP/HTTPS URL (max 300 chars)
//  */
// const isValidSocialUrl = (val) => {
//   if (val === "" || val === undefined || val === null) return true;
//   if (typeof val !== "string") return false;
//   const trimmed = val.trim();
//   if (!trimmed) return true;
//   if (/^@?[\w.-]+$/.test(trimmed)) return true;
//   return isValidHttpUrl(val);
// };

// const ALLOWED_FONT_FAMILIES = [
//   "Arial",
//   "Georgia",
//   "Verdana",
//   "Trebuchet MS",
//   "Tahoma",
//   "Inter",
//   "Roboto",
//   "DM Sans",
//   "Montserrat",
//   "Commissioner",
// ];

// const ALLOWED_LAYOUTS = [
//   "two-column",
//   "horizontal",
//   "compact",
//   "single",
//   "corporate-card",
// ];

// const ALLOWED_SOCIAL_ICONS_STYLES = [
//   "filled",
//   "outline",
//   "circle",
//   "minimal",
// ];

// const ALLOWED_THEMES = ["corporate", "minimal", "modern", "dark"];
// const ALLOWED_SHAPES = ["rounded", "square", "pill"];
// const ALLOWED_BUTTON_STYLES = ["solid", "outline"];
// const ALLOWED_ALIGNS = ["left", "center", "right"];
// const ALLOWED_SIZES = ["sm", "md", "lg"];
// const ALLOWED_COLUMNS = ["left", "right", "full"];
// const ALLOWED_ORIENTATIONS = ["horizontal", "vertical"];

// /**
//  * Helper to validate enum fields with descriptive error messages
//  * that include the received value and the allowed options.
//  */
// function friendlyEnum(name, allowedValues, isOptional = false) {
//   return z
//     .any()
//     .superRefine((val, ctx) => {
//       if (val === undefined) {
//         if (!isOptional) {
//           ctx.addIssue({
//             code: z.ZodIssueCode.custom,
//             message: `${name} is required`,
//           });
//         }
//         return;
//       }
//       const checkVal = typeof val === "string" ? val.trim() : val;
//       if (!allowedValues.includes(checkVal)) {
//         const displayVal =
//           typeof val === "object" && val !== null
//             ? JSON.stringify(val)
//             : String(val);
//         ctx.addIssue({
//           code: z.ZodIssueCode.custom,
//           message: `Invalid ${name} "${displayVal}". Allowed values: ${allowedValues.join(", ")}`,
//         });
//       }
//     })
//     .transform((val) => (typeof val === "string" ? val.trim() : val));
// }

// const socialsSchema = z
//   .object({
//     linkedin: z
//       .string()
//       .trim()
//       .max(300, { error: "LinkedIn URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "LinkedIn URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .default(""),
//     twitter: z
//       .string()
//       .trim()
//       .max(300, { error: "Twitter URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "Twitter URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .default(""),
//     facebook: z
//       .string()
//       .trim()
//       .max(300, { error: "Facebook URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "Facebook URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .default(""),
//     instagram: z
//       .string()
//       .trim()
//       .max(300, { error: "Instagram URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "Instagram URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .optional()
//       .default(""),
//   })
//   .strip()
//   .default({});

// const updateSocialsSchema = z
//   .object({
//     linkedin: z
//       .string()
//       .trim()
//       .max(300, { error: "LinkedIn URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "LinkedIn URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .optional(),
//     twitter: z
//       .string()
//       .trim()
//       .max(300, { error: "Twitter URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "Twitter URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .optional(),
//     facebook: z
//       .string()
//       .trim()
//       .max(300, { error: "Facebook URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "Facebook URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .optional(),
//     instagram: z
//       .string()
//       .trim()
//       .max(300, { error: "Instagram URL cannot exceed 300 characters" })
//       .refine(isValidSocialUrl, {
//         error: "Instagram URL must be empty or a valid HTTP/HTTPS URL",
//       })
//       .optional(),
//   })
//   .strip()
//   .optional();

// const optionalSchema = z
//   .object({
//     address: plainTextString({ max: 250 }).optional().default(""),
//     tagline: plainTextString({ max: 150 }).optional().default(""),
//     disclaimer: plainTextString({ max: 1000 }).optional().default(""),
//   })
//   .strip()
//   .default({});

// const updateOptionalSchema = z
//   .object({
//     address: plainTextString({ max: 250 }).optional(),
//     tagline: plainTextString({ max: 150 }).optional(),
//     disclaimer: plainTextString({ max: 1000 }).optional(),
//   })
//   .strip()
//   .optional();

// /**
//  * Optional design configuration (Design Studio).
//  * Rejects premium themes (luxury, glass, neon) and shapes (glass, blob).
//  */
// const designSchema = z
//   .object({
//     theme: friendlyEnum("theme", ALLOWED_THEMES),
//     shape: friendlyEnum("shape", ALLOWED_SHAPES),
//     buttonStyle: friendlyEnum("buttonStyle", ALLOWED_BUTTON_STYLES),
//   })
//   .strip();

// const updateDesignSchema = z
//   .object({
//     theme: friendlyEnum("theme", ALLOWED_THEMES, true).optional(),
//     shape: friendlyEnum("shape", ALLOWED_SHAPES, true).optional(),
//     buttonStyle: friendlyEnum("buttonStyle", ALLOWED_BUTTON_STYLES, true).optional(),
//   })
//   .strip();

// /**
//  * Discriminated union of extra items (maximum 20 items in extras array).
//  */
// const extraTextSchema = z
//   .object({
//     type: z.literal("text"),
//     id: z
//       .string({ error: "Item ID is required" })
//       .trim()
//       .min(1, { error: "Item ID cannot be empty" })
//       .max(40, { error: "Item ID cannot exceed 40 characters" }),
//     text: plainTextString({ max: 300, required: true }),
//     align: friendlyEnum("align", ALLOWED_ALIGNS),
//     size: friendlyEnum("size", ALLOWED_SIZES),
//     bold: z.boolean({ error: "Bold must be a boolean" }),
//     width: z
//       .number({ error: "Width must be a number" })
//       .int({ error: "Width must be an integer" })
//       .min(20, { error: "Width must be between 20 and 600" })
//       .max(600, { error: "Width must be between 20 and 600" })
//       .optional(),
//     column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
//   })
//   .strip();

// const extraImageSchema = z
//   .object({
//     type: z.literal("image"),
//     id: z
//       .string({ error: "Item ID is required" })
//       .trim()
//       .min(1, { error: "Item ID cannot be empty" })
//       .max(40, { error: "Item ID cannot exceed 40 characters" }),
//     url: z
//       .string({ error: "Image URL is required" })
//       .trim()
//       .refine(isValidS3Url, {
//         error:
//           "Image URL must be an HTTPS URL hosted on authorized storage",
//       }),
//     width: z
//       .number({ error: "Width must be a number" })
//       .int({ error: "Width must be an integer" })
//       .min(20, { error: "Width must be between 20 and 600" })
//       .max(600, { error: "Width must be between 20 and 600" }),
//     align: friendlyEnum("align", ALLOWED_ALIGNS),
//     linkUrl: z
//       .string()
//       .trim()
//       .max(300, { error: "Link URL cannot exceed 300 characters" })
//       .refine(isValidHttpUrl, {
//         error: "Link URL must be a valid HTTP or HTTPS URL",
//       })
//       .optional(),
//     column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
//   })
//   .strip();

// const extraDividerSchema = z
//   .object({
//     type: z.literal("divider"),
//     id: z
//       .string({ error: "Item ID is required" })
//       .trim()
//       .min(1, { error: "Item ID cannot be empty" })
//       .max(40, { error: "Item ID cannot exceed 40 characters" }),
//     width: z
//       .number({ error: "Width must be a number" })
//       .int({ error: "Width must be an integer" })
//       .min(20, { error: "Width must be between 20 and 600" })
//       .max(600, { error: "Width must be between 20 and 600" })
//       .optional(),
//     align: friendlyEnum("align", ALLOWED_ALIGNS, true).optional(),
//     thickness: z
//       .number({ error: "Thickness must be a number" })
//       .int({ error: "Thickness must be an integer" })
//       .min(1, { error: "Thickness must be between 1 and 20" })
//       .max(20, { error: "Thickness must be between 1 and 20" })
//       .optional(),
//     orientation: friendlyEnum("orientation", ALLOWED_ORIENTATIONS, true).optional(),
//     column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
//   })
//   .strip();

// const extraCtaSchema = z
//   .object({
//     type: z.literal("cta"),
//     id: z
//       .string({ error: "Item ID is required" })
//       .trim()
//       .min(1, { error: "Item ID cannot be empty" })
//       .max(40, { error: "Item ID cannot exceed 40 characters" }),
//     label: plainTextString({ max: 40, required: true }),
//     url: z
//       .string({ error: "URL is required" })
//       .trim()
//       .max(300, { error: "URL cannot exceed 300 characters" })
//       .refine(
//         (val) => {
//           if (!val) return false;
//           try {
//             const parsed = new URL(val);
//             return (
//               parsed.protocol === "http:" || parsed.protocol === "https:"
//             );
//           } catch {
//             return false;
//           }
//         },
//         { error: "URL must be a valid HTTP or HTTPS URL" }
//       ),
//     align: friendlyEnum("align", ALLOWED_ALIGNS),
//     width: z
//       .number({ error: "Width must be a number" })
//       .int({ error: "Width must be an integer" })
//       .min(20, { error: "Width must be between 20 and 600" })
//       .max(600, { error: "Width must be between 20 and 600" })
//       .optional(),
//     column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
//   })
//   .strip();

// const extraBannerSchema = z
//   .object({
//     type: z.literal("banner"),
//     id: z
//       .string({ error: "Item ID is required" })
//       .trim()
//       .min(1, { error: "Item ID cannot be empty" })
//       .max(40, { error: "Item ID cannot exceed 40 characters" }),
//     imageUrl: z
//       .string({ error: "Banner image URL is required" })
//       .trim()
//       .refine(isValidS3Url, {
//         error:
//           "Banner image URL must be an HTTPS URL hosted on authorized storage",
//       }),
//     linkUrl: z
//       .string()
//       .trim()
//       .max(300, { error: "Link URL cannot exceed 300 characters" })
//       .refine(isValidHttpUrl, {
//         error: "Link URL must be a valid HTTP or HTTPS URL",
//       })
//       .optional(),
//     column: friendlyEnum("column", ALLOWED_COLUMNS, true).optional(),
//   })
//   .strip();

// const extraItemSchema = z.discriminatedUnion(
//   "type",
//   [
//     extraTextSchema,
//     extraImageSchema,
//     extraDividerSchema,
//     extraCtaSchema,
//     extraBannerSchema,
//   ],
//   {
//     error:
//       "Extra item type must be one of 'text', 'image', 'divider', 'cta', or 'banner'",
//   }
// );

// const extrasSchema = z
//   .array(extraItemSchema, {
//     error: "Extras must be an array",
//   })
//   .max(20, { error: "Extras cannot exceed 20 items" })
//   .optional();

// const freeTextSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("text"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//     text: plainTextString({ max: 1000 }).default(""),
//     size: friendlyEnum("size", ALLOWED_SIZES, true).default("md"),
//     bold: z.boolean().default(false),
//     align: friendlyEnum("align", ALLOWED_ALIGNS, true).default("left"),
//     bind: friendlyEnum("bind", ["name", "jobTitle", "email", "phone"], true).optional(),
//   })
//   .passthrough();

// const freeImageSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("image"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//     url: z.string().max(2000).default(""),
//     linkUrl: z.string().max(2000).optional(),
//     bind: friendlyEnum("bind", ["photo"], true).optional(),
//   })
//   .passthrough();

// const freeLogoSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("logo"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//     url: z.string().max(2000).default(""),
//     linkUrl: z.string().max(2000).optional(),
//   })
//   .passthrough();

// const freeBannerSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("banner"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//     url: z.string().max(2000).default(""),
//     linkUrl: z.string().max(2000).optional(),
//   })
//   .passthrough();

// const freeDividerSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("divider"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//     orientation: friendlyEnum("orientation", ALLOWED_ORIENTATIONS, true).default("horizontal"),
//     thickness: z.number().min(1).max(50).default(1),
//   })
//   .passthrough();

// const freeCtaSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("cta"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//     label: plainTextString({ max: 200 }).default("Button"),
//     url: z.string().max(2000).default("#"),
//   })
//   .passthrough();

// const freeSocialSchema = z
//   .object({
//     id: z.string().min(1).max(64),
//     type: z.literal("social"),
//     x: z.number(),
//     y: z.number(),
//     w: z.number(),
//     h: z.number(),
//     locked: z.boolean().optional(),
//   })
//   .passthrough();

// const freeElementSchema = z.discriminatedUnion("type", [
//   freeTextSchema,
//   freeImageSchema,
//   freeLogoSchema,
//   freeBannerSchema,
//   freeDividerSchema,
//   freeCtaSchema,
//   freeSocialSchema,
// ]);

// const freeElementsSchema = z.array(freeElementSchema).max(50).optional();

// const canvasSchema = z
//   .object({
//     width: z.number().int().min(100).max(1200).default(600),
//     height: z.number().int().min(50).max(2000).default(200),
//   })
//   .passthrough()
//   .optional();

// const themeColorSchema = z
//   .string({ error: "Theme color must be a string" })
//   .trim()
//   .regex(/^#[0-9a-fA-F]{6}$/, {
//     error: "Theme color must be a valid hex color code matching #RRGGBB",
//   });

// /**
//  * Signature data schema with defaults for POST /api/v1/signatures.
//  * Missing styling fields default to brand and template defaults.
//  */
// const signatureDataSchema = z
//   .object({
//     fullName: plainTextString({ max: 100 }).default(""),
//     jobTitle: plainTextString({ max: 100 }).default(""),
//     companyName: plainTextString({ max: 100 }).default(""),
//     email: plainTextString({ max: 254 }).default(""),
//     phone: plainTextString({ max: 40 }).default(""),
//     website: plainTextString({ max: 200 }).default(""),
//     avatarUrl: z
//       .string()
//       .trim()
//       .refine((val) => val === "" || isValidImageUrl(val), {
//         error:
//           "Avatar URL must be empty, a relative path starting with '/', or an HTTPS URL hosted on authorized storage",
//       })
//       .optional()
//       .default(""),
//     companyLogoUrl: z
//       .string()
//       .trim()
//       .refine((val) => val === "" || isValidImageUrl(val), {
//         error:
//           "Company logo URL must be empty, a relative path starting with '/', or an HTTPS URL hosted on authorized storage",
//       })
//       .optional()
//       .default(""),
//     themeColor: themeColorSchema.default("#2563eb"),
//     fontFamily: friendlyEnum("fontFamily", ALLOWED_FONT_FAMILIES).default("Arial"),
//     layout: friendlyEnum("layout", ALLOWED_LAYOUTS).default("two-column"),
//     socialIconsStyle: friendlyEnum("socialIconsStyle", ALLOWED_SOCIAL_ICONS_STYLES).default("filled"),
//     design: designSchema.optional(),
//     extras: extrasSchema,
//     socials: socialsSchema,
//     optional: optionalSchema,
//     address: plainTextString({ max: 250 }).optional(),
//     tagline: plainTextString({ max: 150 }).optional(),
//     disclaimer: plainTextString({ max: 1000 }).optional(),
//     canvas: canvasSchema,
//     elements: freeElementsSchema,
//   })
//   .passthrough();

// /**
//  * Partial signature data schema for PATCH /api/v1/signatures/:id.
//  * Fields are optional and do NOT have defaults, preventing silent overwrite of existing values.
//  */
// const updateSignatureDataSchema = z
//   .object({
//     fullName: plainTextString({ max: 100 }).optional(),
//     jobTitle: plainTextString({ max: 100 }).optional(),
//     companyName: plainTextString({ max: 100 }).optional(),
//     email: plainTextString({ max: 254 }).optional(),
//     phone: plainTextString({ max: 40 }).optional(),
//     website: plainTextString({ max: 200 }).optional(),
//     avatarUrl: z
//       .string()
//       .trim()
//       .refine((val) => val === "" || isValidImageUrl(val), {
//         error:
//           "Avatar URL must be empty, a relative path starting with '/', or an HTTPS URL hosted on authorized storage",
//       })
//       .optional(),
//     companyLogoUrl: z
//       .string()
//       .trim()
//       .refine((val) => val === "" || isValidImageUrl(val), {
//         error:
//           "Company logo URL must be empty, a relative path starting with '/', or an HTTPS URL hosted on authorized storage",
//       })
//       .optional(),
//     themeColor: themeColorSchema.optional(),
//     fontFamily: friendlyEnum("fontFamily", ALLOWED_FONT_FAMILIES, true).optional(),
//     layout: friendlyEnum("layout", ALLOWED_LAYOUTS, true).optional(),
//     socialIconsStyle: friendlyEnum("socialIconsStyle", ALLOWED_SOCIAL_ICONS_STYLES, true).optional(),
//     design: updateDesignSchema.optional(),
//     extras: extrasSchema,
//     socials: updateSocialsSchema,
//     optional: updateOptionalSchema,
//     address: plainTextString({ max: 250 }).optional(),
//     tagline: plainTextString({ max: 150 }).optional(),
//     disclaimer: plainTextString({ max: 1000 }).optional(),
//     canvas: canvasSchema,
//     elements: freeElementsSchema,
//   })
//   .passthrough();

// const createSignatureSchema = z
//   .object({
//     name: plainTextString({ max: 100, required: true }),
//     templateId: z
//       .string({ error: "Template ID is required" })
//       .trim()
//       .min(1, { error: "Template ID cannot be empty" })
//       .max(64, { error: "Template ID cannot exceed 64 characters" })
//       .regex(/^[a-z0-9-]+$/, {
//         error:
//           "Template ID must contain only lowercase letters, digits, and dashes",
//       }),
//     templateVersion: z
//       .number({ error: "Template version must be a number" })
//       .int({ error: "Template version must be an integer" })
//       .min(1, { error: "Template version must be between 1 and 1000" })
//       .max(1000, { error: "Template version must be between 1 and 1000" })
//       .default(1),
//     data: z.preprocess(
//       (val) => (val === undefined ? {} : val),
//       signatureDataSchema
//     ),
//   })
//   .strip()
//   .refine(
//     (body) => Buffer.byteLength(JSON.stringify(body.data), "utf8") <= 65536,
//     {
//       error: "Signature data payload size cannot exceed 64 KB",
//       path: ["data"],
//     }
//   );

// const updateSignatureSchema = z
//   .object({
//     name: plainTextString({ max: 100, required: true }).optional(),
//     templateId: z
//       .string({ error: "Template ID must be a string" })
//       .trim()
//       .min(1, { error: "Template ID cannot be empty" })
//       .max(64, { error: "Template ID cannot exceed 64 characters" })
//       .regex(/^[a-z0-9-]+$/, {
//         error:
//           "Template ID must contain only lowercase letters, digits, and dashes",
//       })
//       .optional(),
//     templateVersion: z
//       .number({ error: "Template version must be a number" })
//       .int({ error: "Template version must be an integer" })
//       .min(1, { error: "Template version must be between 1 and 1000" })
//       .max(1000, { error: "Template version must be between 1 and 1000" })
//       .optional(),
//     data: updateSignatureDataSchema.optional(),
//   })
//   .strip()
//   .refine(
//     (body) => {
//       return (
//         body.name !== undefined ||
//         body.templateId !== undefined ||
//         body.templateVersion !== undefined ||
//         body.data !== undefined
//       );
//     },
//     {
//       error:
//         "At least one field (name, templateId, templateVersion, or data) must be provided for update",
//     }
//   )
//   .refine(
//     (body) => {
//       if (!body.data) return true;
//       return Buffer.byteLength(JSON.stringify(body.data), "utf8") <= 65536;
//     },
//     {
//       error: "Signature data payload size cannot exceed 64 KB",
//       path: ["data"],
//     }
//   );

// const signatureIdParamSchema = z
//   .object({
//     id: z
//       .string({ error: "Signature ID is required" })
//       .trim()
//       .min(1, { error: "Signature ID cannot be empty" })
//       .max(64, { error: "Signature ID cannot exceed 64 characters" }),
//   })
//   .strip();

// module.exports = {
//   createSignatureSchema,
//   updateSignatureSchema,
//   signatureIdParamSchema,
//   signatureDataSchema,
//   updateSignatureDataSchema,
//   isValidImageUrl,
//   isValidS3Url,
//   ALLOWED_FONT_FAMILIES,
//   ALLOWED_LAYOUTS,
//   ALLOWED_SOCIAL_ICONS_STYLES,
// };
