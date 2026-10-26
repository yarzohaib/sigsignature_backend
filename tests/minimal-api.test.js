const { test, describe } = require("node:test");
const assert = require("node:assert/strict");

const { validate } = require("../src/middleware/validate.middleware");
const {
  createSignatureSchema,
  updateSignatureSchema,
  ALLOWED_FONT_FAMILIES,
  ALLOWED_LAYOUTS,
  ALLOWED_SOCIAL_ICONS_STYLES,
} = require("../src/validators/signature.validator");
const { presignUploadSchema } = require("../src/validators/upload.validator");
const signatureService = require("../src/services/signature.service");
const signatureRepository = require("../src/repositories/signature.repository");

/**
 * Lightweight mock Express pipeline runner (socket-free).
 */
function runValidation(middleware, body) {
  return new Promise((resolve) => {
    const req = { body: JSON.parse(JSON.stringify(body)) };
    let statusCode = 200;
    let responseBody = null;

    const res = {
      status(code) {
        statusCode = code;
        return this;
      },
      json(data) {
        responseBody = data;
        resolve({ status: statusCode, body: responseBody, reqBody: req.body });
        return this;
      },
    };

    middleware(req, res, () => {
      // If validation succeeds, next() is called
      resolve({ status: 200, body: null, reqBody: req.body });
    });
  });
}

describe("Minimal API Requests & Friendly Validation Suite", () => {
  // 1. POST /api/v1/signatures minimal body and defaults
  test("1. Minimal signature body succeeds and populates styling defaults", async () => {
    const postValidator = validate(createSignatureSchema);

    // Minimal body: only name and templateId
    const minimalBody = {
      name: "Minimal Signature",
      templateId: "corporate",
    };

    const res1 = await runValidation(postValidator, minimalBody);
    assert.equal(res1.status, 200, "Minimal body without data should pass validation");
    assert.equal(res1.reqBody.name, "Minimal Signature");
    assert.equal(res1.reqBody.templateId, "corporate");
    assert.equal(res1.reqBody.templateVersion, 1);

    // Verify styling defaults
    assert.equal(res1.reqBody.data.themeColor, "#2563eb", "themeColor should default to #2563eb");
    assert.equal(res1.reqBody.data.fontFamily, "Arial", "fontFamily should default to Arial");
    assert.equal(res1.reqBody.data.layout, "two-column", "layout should default to two-column (Corporate template)");
    assert.equal(res1.reqBody.data.socialIconsStyle, "filled", "socialIconsStyle should default to filled");

    // Verify text and sub-object defaults
    assert.equal(res1.reqBody.data.fullName, "");
    assert.equal(res1.reqBody.data.jobTitle, "");
    assert.equal(res1.reqBody.data.companyName, "");
    assert.equal(res1.reqBody.data.email, "");
    assert.deepEqual(res1.reqBody.data.socials, {});
    assert.deepEqual(res1.reqBody.data.optional, {});

    // Minimal body with explicit empty data: {}
    const res2 = await runValidation(postValidator, {
      name: "Minimal Signature With Empty Data",
      templateId: "corporate",
      data: {},
    });
    assert.equal(res2.status, 200);
    assert.equal(res2.reqBody.data.themeColor, "#2563eb");
    assert.equal(res2.reqBody.data.fontFamily, "Arial");
    assert.equal(res2.reqBody.data.layout, "two-column");
    assert.equal(res2.reqBody.data.socialIconsStyle, "filled");
  });

  // 2. Strict validation when invalid values are provided
  test("2. Invalid themeColor, unknown font, or unknown layout returns 400 with descriptive error", async () => {
    const postValidator = validate(createSignatureSchema);

    // Invalid color (non-hex or short hex)
    const badColor = await runValidation(postValidator, {
      name: "Bad Color Sig",
      templateId: "corporate",
      data: { themeColor: "red" },
    });
    assert.equal(badColor.status, 400);
    assert.equal(badColor.body.success, false);
    assert.match(badColor.body.message, /Theme color must be a valid hex color code/);

    const badColor2 = await runValidation(postValidator, {
      name: "Bad Hex Sig",
      templateId: "corporate",
      data: { themeColor: "#123" },
    });
    assert.equal(badColor2.status, 400);

    // Unknown layout with descriptive error showing received value and allowed values
    const badLayout = await runValidation(postValidator, {
      name: "Bad Layout Sig",
      templateId: "corporate",
      data: { layout: "three-columns-floating" },
    });
    assert.equal(badLayout.status, 400);
    assert.equal(
      badLayout.body.message,
      'Invalid layout "three-columns-floating". Allowed values: two-column, horizontal, compact, single, corporate-card'
    );
    assert.deepEqual(badLayout.body.errors[0].path, ["data", "layout"]);

    // Unknown fontFamily with descriptive error showing received value and allowed options
    const badFont = await runValidation(postValidator, {
      name: "Bad Font Sig",
      templateId: "corporate",
      data: { fontFamily: "Papyrus" },
    });
    assert.equal(badFont.status, 400);
    assert.equal(
      badFont.body.message,
      `Invalid fontFamily "Papyrus". Allowed values: ${ALLOWED_FONT_FAMILIES.join(", ")}`
    );

    // Unknown socialIconsStyle with descriptive error
    const badSocial = await runValidation(postValidator, {
      name: "Bad Social Sig",
      templateId: "corporate",
      data: { socialIconsStyle: "neon-glow" },
    });
    assert.equal(badSocial.status, 400);
    assert.equal(
      badSocial.body.message,
      "Invalid socialIconsStyle \"neon-glow\". Allowed values: filled, outline, circle, minimal"
    );
  });

  // 3. PATCH does not reset omitted fields
  test("3. PATCH validation does not default omitted styling fields, and service preserves existing values", async () => {
    const patchValidator = validate(updateSignatureSchema);

    // Valid update containing only fullName
    const partialUpdate = await runValidation(patchValidator, {
      data: { fullName: "Updated Full Name" },
    });
    assert.equal(partialUpdate.status, 200);
    assert.equal(partialUpdate.reqBody.data.fullName, "Updated Full Name");
    // Ensure styling fields are NOT defaulted
    assert.equal(partialUpdate.reqBody.data.themeColor, undefined);
    assert.equal(partialUpdate.reqBody.data.fontFamily, undefined);
    assert.equal(partialUpdate.reqBody.data.layout, undefined);
    assert.equal(partialUpdate.reqBody.data.socialIconsStyle, undefined);

    // Verify invalid values on PATCH still fail
    const badPatchColor = await runValidation(patchValidator, {
      data: { themeColor: "invalid-color" },
    });
    assert.equal(badPatchColor.status, 400);

    const badPatchLayout = await runValidation(patchValidator, {
      data: { layout: "unknown-layout" },
    });
    assert.equal(badPatchLayout.status, 400);
    assert.equal(
      badPatchLayout.body.message,
      'Invalid layout "unknown-layout". Allowed values: two-column, horizontal, compact, single, corporate-card'
    );

    // Service-level test verifying DB update merges without resetting omitted fields
    const mockExisting = {
      id: "sig-test-1",
      userId: "user-test-1",
      name: "Original Name",
      templateId: "corporate",
      templateVersion: 1,
      data: {
        fullName: "Original User",
        themeColor: "#10b981", // Custom green
        fontFamily: "Inter",   // Custom font
        layout: "horizontal",  // Custom layout
        socialIconsStyle: "circle", // Custom style
        phone: "+1-555-0199",
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    let updatedPayload = null;
    const originalFind = signatureRepository.findByIdForUser;
    const originalUpdate = signatureRepository.update;

    signatureRepository.findByIdForUser = async (id, userId) => {
      if (id === "sig-test-1" && userId === "user-test-1") {
        return mockExisting;
      }
      return null;
    };

    signatureRepository.update = async (id, userId, payload) => {
      updatedPayload = payload;
      return {
        ...mockExisting,
        ...payload,
        data: {
          ...mockExisting.data,
          ...(payload.data || {}),
        },
      };
    };

    try {
      const result = await signatureService.update("sig-test-1", "user-test-1", {
        data: {
          fullName: "Attempted Name Change",
          phone: "+1-555-9999",
        },
      });

      // Verify that fullName is strictly locked to original identity on Free plan
      assert.equal(updatedPayload.data.fullName, "Original User", "fullName must be locked to original");
      assert.equal(updatedPayload.data.phone, "+1-555-9999", "Other editable fields like phone must update");
      assert.equal(updatedPayload.data.themeColor, "#10b981", "Existing themeColor must be preserved");
      assert.equal(updatedPayload.data.fontFamily, "Inter", "Existing fontFamily must be preserved");
      assert.equal(updatedPayload.data.layout, "horizontal", "Existing layout must be preserved");
      assert.equal(updatedPayload.data.socialIconsStyle, "circle", "Existing socialIconsStyle must be preserved");
    } finally {
      signatureRepository.findByIdForUser = originalFind;
      signatureRepository.update = originalUpdate;
    }
  });

  // 4. Presign upload without kind works and defaults to "avatar"
  test("4. Presign upload without kind defaults to 'avatar'", async () => {
    const presignValidator = validate(presignUploadSchema);

    const validWithoutKind = {
      contentType: "image/png",
      size: 1048576, // 1MB
    };

    const res = await runValidation(presignValidator, validWithoutKind);
    assert.equal(res.status, 200);
    assert.equal(res.reqBody.kind, "avatar", "kind should default to avatar when omitted");
    assert.equal(res.reqBody.contentType, "image/png");
    assert.equal(res.reqBody.size, 1048576);

    // Explicit kind works as expected
    const validWithLogo = {
      kind: "logo",
      contentType: "image/jpeg",
      size: 524288,
    };
    const resLogo = await runValidation(presignValidator, validWithLogo);
    assert.equal(resLogo.status, 200);
    assert.equal(resLogo.reqBody.kind, "logo");
  });

  // 5. Presign upload with invalid kind, contentType, or size returns descriptive 400
  test("5. Presign upload with invalid kind 'xyz' returns descriptive 400 showing received value and options", async () => {
    const presignValidator = validate(presignUploadSchema);

    // Invalid kind
    const badKind = await runValidation(presignValidator, {
      kind: "xyz",
      contentType: "image/png",
      size: 1024,
    });
    assert.equal(badKind.status, 400);
    assert.equal(badKind.body.success, false);
    assert.equal(
      badKind.body.message,
      'Invalid kind "xyz". Allowed values: avatar, logo'
    );
    assert.deepEqual(badKind.body.errors[0].path, ["kind"]);

    // Invalid contentType
    const badContentType = await runValidation(presignValidator, {
      kind: "avatar",
      contentType: "image/gif",
      size: 1024,
    });
    assert.equal(badContentType.status, 400);
    assert.equal(
      badContentType.body.message,
      'Invalid contentType "image/gif". Allowed values: image/jpeg, image/png, image/webp'
    );

    // Invalid size: exceeds 2MB limit
    const badSizeTooLarge = await runValidation(presignValidator, {
      kind: "avatar",
      contentType: "image/png",
      size: 3000000,
    });
    assert.equal(badSizeTooLarge.status, 400);
    assert.equal(
      badSizeTooLarge.body.message,
      'Invalid size "3000000". File size must be between 1 and 2097152 bytes (2MB)'
    );

    // Invalid size: non-integer
    const badSizeNonInteger = await runValidation(presignValidator, {
      kind: "avatar",
      contentType: "image/png",
      size: "not-a-number",
    });
    assert.equal(badSizeNonInteger.status, 400);
    assert.equal(
      badSizeNonInteger.body.message,
      'Invalid size "not-a-number". File size must be an integer'
    );
  });
});
