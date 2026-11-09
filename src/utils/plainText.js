const { z } = require("zod");

/**
 * ARCHITECTURAL DESIGN NOTE:
 * We do NOT HTML-encode user input strings before storing them in the database.
 * Storing clean, unencoded plain text adheres to standard security best practices:
 * 1. Prevents double-escaping bugs (e.g., "R&D" -> "R&amp;D" -> "R&amp;amp;D").
 * 2. Allows consistent search, indexing, filtering, and sorting in database queries.
 * 3. Keeps data clean and format-agnostic across APIs, exports, and plain-text emails.
 * 4. Context-sensitive HTML escaping is strictly performed at render time (e.g., via
 *    escapeHtml() in email templates or signature HTML generators).
 */

/**
 * Creates a Zod string validator for hardened plain-text input.
 * - Trims leading and trailing whitespace
 * - Strips ASCII and Unicode control characters (except standard whitespace \t, \n, \r)
 * - Normalizes Unicode to Canonical Composition (NFC)
 * - Enforces minimum and maximum length restrictions
 * - Strictly rejects HTML markup, tags ("<", ">"), javascript: schemes, and data:text/html
 *
 * @param {Object} options
 * @param {number} [options.max] - Maximum character length
 * @param {number} [options.min=0] - Minimum character length
 * @param {boolean} [options.required=false] - If true, enforces minimum length of at least 1
 * @param {string} [options.error] - Optional custom error message
 * @returns {import("zod").ZodType}
 */
function plainTextString({
  max,
  min = 0,
  required = false,
  error,
} = {}) {
  let schema = z
    .string({ error: error || "Invalid text input" })
    .trim()
    .transform((val) =>
      val
        .normalize("NFC")
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "")
    );

  const minLength = required ? Math.max(1, min) : min;
  if (minLength > 0) {
    schema = schema.refine((val) => val.length >= minLength, {
      message: error || "This field cannot be empty",
    });
  }

  // Check markup/HTML safety before length check to prioritize security feedback
  schema = schema.refine(
    (val) => {
      // Reject any HTML tags or markup characters
      if (val.includes("<") || val.includes(">")) {
        return false;
      }
      // Reject dangerous script protocols / data URIs in text fields
      const lower = val.toLowerCase();
      if (lower.includes("javascript:") || lower.includes("data:text/html")) {
        return false;
      }
      return true;
    },
    {
      message: "This field cannot contain HTML or markup",
    }
  );

  if (typeof max === "number") {
    schema = schema.refine((val) => val.length <= max, {
      message: error || `Cannot exceed ${max} characters`,
    });
  }

  return schema;
}

/**
 * Strips angle brackets from a string to neutralize legacy/unvalidated stored HTML tags.
 * @param {any} val
 * @returns {any}
 */
function stripAngleBrackets(val) {
  if (typeof val !== "string") return val;
  return val.replace(/[<>]/g, "");
}

/**
 * Sanitizes signature data on read to neutralize old stored payloads containing markup.
 * @param {Object} data
 * @returns {Object}
 */
function sanitizeSignatureData(data) {
  if (!data || typeof data !== "object") return data;
  const copy = { ...data };

  // Core free text fields
  const textFields = [
    "fullName",
    "jobTitle",
    "companyName",
    "email",
    "phone",
    "website",
    "address",
    "tagline",
    "disclaimer",
  ];
  for (const field of textFields) {
    if (typeof copy[field] === "string") {
      copy[field] = stripAngleBrackets(copy[field]);
    }
  }

  // Nested optional fields
  if (copy.optional && typeof copy.optional === "object") {
    copy.optional = { ...copy.optional };
    for (const field of ["address", "tagline", "disclaimer"]) {
      if (typeof copy.optional[field] === "string") {
        copy.optional[field] = stripAngleBrackets(copy.optional[field]);
      }
    }
  }

  // Extras array
  if (Array.isArray(copy.extras)) {
    copy.extras = copy.extras.map((item) => {
      if (!item || typeof item !== "object") return item;
      const itemCopy = { ...item };
      if (itemCopy.type === "text" && typeof itemCopy.text === "string") {
        itemCopy.text = stripAngleBrackets(itemCopy.text);
      }
      if (itemCopy.type === "cta" && typeof itemCopy.label === "string") {
        itemCopy.label = stripAngleBrackets(itemCopy.label);
      }
      return itemCopy;
    });
  }

  // Free canvas elements array
  if (Array.isArray(copy.elements)) {
    copy.elements = copy.elements.map((el) => {
      if (!el || typeof el !== "object") return el;
      const elCopy = { ...el };
      if (elCopy.type === "text" && typeof elCopy.text === "string") {
        elCopy.text = stripAngleBrackets(elCopy.text);
      }
      if (elCopy.type === "cta" && typeof elCopy.label === "string") {
        elCopy.label = stripAngleBrackets(elCopy.label);
      }
      return elCopy;
    });
  }

  return copy;
}

/**
 * Sanitizes a complete signature entity on read.
 * @param {Object} signature
 * @returns {Object}
 */
function sanitizeSignature(signature) {
  if (!signature) return signature;
  const sanitized = {
    ...signature,
    name: stripAngleBrackets(signature.name),
  };
  if (signature.data) {
    sanitized.data = sanitizeSignatureData(signature.data);
  }
  return sanitized;
}

module.exports = {
  plainTextString,
  stripAngleBrackets,
  sanitizeSignatureData,
  sanitizeSignature,
};
