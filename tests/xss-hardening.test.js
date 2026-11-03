const { test, describe } = require("node:test");
const assert = require("node:assert/strict");

const { validate } = require("../src/middleware/validate.middleware");
const {
  createSignatureSchema,
  updateSignatureSchema,
  ALLOWED_FONT_FAMILIES,
} = require("../src/validators/signature.validator");
const {
  createTeamSchema,
  updateMemberSchema,
} = require("../src/validators/team.validator");
const {
  updateProfileSchema,
  updateSettingsSchema,
} = require("../src/validators/account.validator");
const {
  plainTextString,
  stripAngleBrackets,
  sanitizeSignatureData,
  sanitizeSignature,
} = require("../src/utils/plainText");
const {
  renderTemplate,
  escapeHtml,
} = require("../src/services/mail.service");

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

function getValidSignatureBody(overrides = {}) {
  const baseData = {
    fullName: "Jane Doe",
    jobTitle: "Head of Engineering",
    companyName: "Acme Corp",
    email: "jane.doe@acme.com",
    phone: "+1 555 123 4567",
    website: "https://acme.com",
    themeColor: "#10B981",
    fontFamily: "Inter",
    layout: "two-column",
    socialIconsStyle: "filled",
    socials: {
      linkedin: "https://linkedin.com/in/janedoe",
    },
    optional: {
      address: "100 Market St, San Francisco, CA",
      tagline: "Building tomorrow's tools today",
      disclaimer: "This email and any attachments are confidential.",
    },
    extras: [
      {
        type: "text",
        id: "extra-1",
        text: "Certified Solutions Architect",
        align: "left",
        size: "sm",
        bold: false,
      },
    ],
  };

  const { data: dataOverrides, ...rootOverrides } = overrides;

  return {
    name: "Standard Work Signature",
    templateId: "classic-clean",
    templateVersion: 1,
    ...rootOverrides,
    data: {
      ...baseData,
      ...(dataOverrides || {}),
    },
  };
}

describe("XSS Hardening & Free-Text Validation Suite", () => {
  // 1. Report's payload: <img src=x onerror=alert(1)> returns 400 on POST and PATCH
  test("1. POST /api/v1/signatures rejects '<img src=x onerror=alert(1)>' with 400", async () => {
    const postValidator = validate(createSignatureSchema);

    // Payload in signature name
    const res1 = await runValidation(
      postValidator,
      getValidSignatureBody({ name: "<img src=x onerror=alert(1)>" })
    );
    assert.equal(res1.status, 400);
    assert.equal(res1.body.success, false);
    assert.equal(res1.body.message, "This field cannot contain HTML or markup");

    // Payload in data.fullName
    const res2 = await runValidation(
      postValidator,
      getValidSignatureBody({ data: { fullName: "<img src=x onerror=alert(1)>" } })
    );
    assert.equal(res2.status, 400);
    assert.equal(res2.body.message, "This field cannot contain HTML or markup");

    // Payload in data.optional.disclaimer
    const res3 = await runValidation(
      postValidator,
      getValidSignatureBody({
        data: {
          optional: { disclaimer: "Confidential <img src=x onerror=alert(1)>" },
        },
      })
    );
    assert.equal(res3.status, 400);
    assert.equal(res3.body.message, "This field cannot contain HTML or markup");

    // Payload in data.extras text
    const res4 = await runValidation(
      postValidator,
      getValidSignatureBody({
        data: {
          extras: [
            {
              type: "text",
              id: "item-1",
              text: "<img src=x onerror=alert(1)>",
              align: "left",
              size: "sm",
              bold: false,
            },
          ],
        },
      })
    );
    assert.equal(res4.status, 400);
    assert.equal(res4.body.message, "This field cannot contain HTML or markup");
  });

  test("2. PATCH /api/v1/signatures/:id rejects '<img src=x onerror=alert(1)>' with 400", async () => {
    const patchValidator = validate(updateSignatureSchema);

    // In signature name
    const res1 = await runValidation(patchValidator, {
      name: "<img src=x onerror=alert(1)>",
    });
    assert.equal(res1.status, 400);
    assert.equal(res1.body.success, false);
    assert.equal(res1.body.message, "This field cannot contain HTML or markup");

    // In data.jobTitle
    const res2 = await runValidation(patchValidator, {
      data: {
        themeColor: "#2563EB",
        fontFamily: "Arial",
        layout: "compact",
        socialIconsStyle: "circle",
        jobTitle: "<img src=x onerror=alert(1)>",
      },
    });
    assert.equal(res2.status, 400);
    assert.equal(res2.body.message, "This field cannot contain HTML or markup");
  });

  // 2. SVG and script payloads are rejected
  test("3. SVG, script, and HTML tag payloads are strictly rejected", async () => {
    const postValidator = validate(createSignatureSchema);

    const dangerousPayloads = [
      "<script>alert(1)</script>",
      "<SCRIPT SRC='https://attacker.com/evil.js'></SCRIPT>",
      "<svg onload=alert(1)>",
      "<svg/onload=alert('XSS')>",
      "<iframe src='javascript:alert(1)'></iframe>",
      "<a href='javascript:void(0)'>Click here</a>",
      "<b>Bold</b> text",
      "<div>Testing</div>",
    ];

    for (const payload of dangerousPayloads) {
      const res = await runValidation(
        postValidator,
        getValidSignatureBody({ name: payload })
      );
      assert.equal(
        res.status,
        400,
        `Expected payload "${payload}" to be rejected with 400`
      );
      assert.equal(res.body.message, "This field cannot contain HTML or markup");
    }
  });

  // 3. javascript: and data:text/html are rejected
  test("4. javascript: and data:text/html schemes are rejected in text fields", async () => {
    const postValidator = validate(createSignatureSchema);

    const res1 = await runValidation(
      postValidator,
      getValidSignatureBody({ name: "javascript:alert(document.cookie)" })
    );
    assert.equal(res1.status, 400);
    assert.equal(res1.body.message, "This field cannot contain HTML or markup");

    const res2 = await runValidation(
      postValidator,
      getValidSignatureBody({ name: "JAVASCRIPT:void(0)" })
    );
    assert.equal(res2.status, 400);
    assert.equal(res2.body.message, "This field cannot contain HTML or markup");

    const res3 = await runValidation(
      postValidator,
      getValidSignatureBody({
        name: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      })
    );
    assert.equal(res3.status, 400);
    assert.equal(res3.body.message, "This field cannot contain HTML or markup");
  });

  // 4. "R&D Team" and "O'Brien" still save and come back unchanged (NOT HTML encoded)
  test("5. 'R&D Team' and 'O'Brien' pass validation and are NOT HTML-encoded in storage", async () => {
    const postValidator = validate(createSignatureSchema);

    const body = getValidSignatureBody({
      name: "O'Brien & Sons Legal",
      data: {
        fullName: "Conan O'Brien",
        companyName: "R&D Team & Partners",
        tagline: "Research & Development Specialists (R&D)",
      },
    });

    const res = await runValidation(postValidator, body);
    assert.equal(res.status, 200, "Validation should succeed for safe special characters");

    // Must be stored as raw clean text, NOT HTML encoded
    assert.equal(res.reqBody.name, "O'Brien & Sons Legal");
    assert.equal(res.reqBody.data.fullName, "Conan O'Brien");
    assert.equal(res.reqBody.data.companyName, "R&D Team & Partners");
    assert.equal(res.reqBody.data.tagline, "Research & Development Specialists (R&D)");

    // Explicitly verify NO HTML-entity encoding occurred
    assert.ok(!res.reqBody.name.includes("&amp;"));
    assert.ok(!res.reqBody.name.includes("&#39;"));
    assert.ok(!res.reqBody.data.companyName.includes("&amp;"));
  });

  // 5. Valid HTTPS links still work
  test("6. Valid HTTPS links and S3 assets still pass validation", async () => {
    const postValidator = validate(createSignatureSchema);

    const body = getValidSignatureBody({
      data: {
        website: "https://www.sigsignature.com",
        avatarUrl:
          "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com/avatars/user-123.jpg",
        companyLogoUrl:
          "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com/logos/company.png",
        socials: {
          linkedin: "https://linkedin.com/in/janedoe",
          twitter: "https://x.com/janedoe",
        },
      },
    });

    const res = await runValidation(postValidator, body);
    assert.equal(res.status, 200);
    assert.equal(res.reqBody.data.website, "https://www.sigsignature.com");
    assert.equal(
      res.reqBody.data.avatarUrl,
      "https://sigsignature-prod-assets-2026.s3.ap-southeast-2.amazonaws.com/avatars/user-123.jpg"
    );
  });

  // 6. Color and font validation patterns
  test("7. Strict themeColor hex regex and fontFamily enum enforcement", async () => {
    const postValidator = validate(createSignatureSchema);

    // Invalid color (CSS injection attempt)
    const badColor1 = await runValidation(
      postValidator,
      getValidSignatureBody({ data: { themeColor: "red; background: blue" } })
    );
    assert.equal(badColor1.status, 400);

    const badColor2 = await runValidation(
      postValidator,
      getValidSignatureBody({ data: { themeColor: "#123" } }) // Must be 6 hex digits
    );
    assert.equal(badColor2.status, 400);

    // Invalid font (CSS injection attempt)
    const badFont = await runValidation(
      postValidator,
      getValidSignatureBody({
        data: { fontFamily: "Arial; font-size: 100px; color: red" },
      })
    );
    assert.equal(badFont.status, 400);

    // Valid colors and fonts
    for (const font of ALLOWED_FONT_FAMILIES) {
      const valid = await runValidation(
        postValidator,
        getValidSignatureBody({
          data: { themeColor: "#00FF00", fontFamily: font },
        })
      );
      assert.equal(valid.status, 200, `Font family "${font}" should be accepted`);
    }
  });

  // 7. Team & Account validators protection
  test("8. Team and Account validators reject markup and enforce strict patterns", async () => {
    const teamValidator = validate(createTeamSchema);
    const badTeam = await runValidation(teamValidator, {
      signatureId: "sig-123",
      name: "<script>alert('team')</script>",
    });
    assert.equal(badTeam.status, 400);
    assert.equal(badTeam.body.message, "This field cannot contain HTML or markup");

    const memberValidator = validate(updateMemberSchema);
    const badMember = await runValidation(memberValidator, {
      name: "<img src=x onerror=alert(1)>",
    });
    assert.equal(badMember.status, 400);
    assert.equal(badMember.body.message, "This field cannot contain HTML or markup");

    const profileValidator = validate(updateProfileSchema);
    const badProfile = await runValidation(profileValidator, {
      firstName: "<svg onload=alert(1)>",
    });
    assert.equal(badProfile.status, 400);
    assert.equal(badProfile.body.message, "This field cannot contain HTML or markup");

    // Enforces firstName min 2 and max 50 chars, and auto-trimming
    const shortFirst = await runValidation(profileValidator, {
      firstName: "A",
    });
    assert.equal(shortFirst.status, 400);

    const whitespaceFirst = await runValidation(profileValidator, {
      firstName: "   ",
    });
    assert.equal(whitespaceFirst.status, 400);

    const longFirst = await runValidation(profileValidator, {
      firstName: "A".repeat(51),
    });
    assert.equal(longFirst.status, 400);

    // Enforces lastName max 50 chars
    const longLast = await runValidation(profileValidator, {
      lastName: "B".repeat(51),
    });
    assert.equal(longLast.status, 400);

    const settingsValidator = validate(updateSettingsSchema);
    const badSettingsColor = await runValidation(settingsValidator, {
      brandColor: "expression(alert(1))",
    });
    assert.equal(badSettingsColor.status, 400);

    const badSettingsFont = await runValidation(settingsValidator, {
      signatureFont: "MaliciousFontName",
    });
    assert.equal(badSettingsFont.status, 400);
  });

  // 8. Sanitization on READ for legacy records
  test("9. Sanitization on READ strips angle brackets from legacy database rows", () => {
    const legacyRow = {
      id: "sig-legacy-01",
      userId: "user-1",
      name: "Old <script>alert(1)</script> Signature",
      data: {
        fullName: "Alice <img src=x onerror=alert(1)> In Wonderland",
        jobTitle: "Senior <Developer>",
        companyName: "R&D Team",
        optional: {
          tagline: "Leading the <<future>>",
          disclaimer: "Standard <legal> notice",
        },
        extras: [
          {
            type: "text",
            id: "t1",
            text: "Extra <blink>alert</blink>",
          },
          {
            type: "cta",
            id: "c1",
            label: "Click <Me>",
          },
        ],
      },
    };

    const sanitized = sanitizeSignature(legacyRow);

    // Angle brackets are stripped on read
    assert.equal(sanitized.name, "Old scriptalert(1)/script Signature");
    assert.equal(
      sanitized.data.fullName,
      "Alice img src=x onerror=alert(1) In Wonderland"
    );
    assert.equal(sanitized.data.jobTitle, "Senior Developer");
    assert.equal(sanitized.data.companyName, "R&D Team");
    assert.equal(sanitized.data.optional.tagline, "Leading the future");
    assert.equal(sanitized.data.optional.disclaimer, "Standard legal notice");
    assert.equal(sanitized.data.extras[0].text, "Extra blinkalert/blink");
    assert.equal(sanitized.data.extras[1].label, "Click Me");

    // Non-markup characters like "&" and "'" remain untouched
    assert.ok(sanitized.data.companyName.includes("&"));
  });

  // 9. Email template rendering escaping
  test("10. Mail service renderTemplate automatically escapes all user-supplied values", () => {
    const template = "<p>Hello {{firstName}}, welcome to {{teamName}}!</p><a href=\"{{actionUrl}}\">Click here</a>";

    const rendered = renderTemplate(template, {
      firstName: "<script>alert('xss')</script>",
      teamName: "R&D \"VIP\" <Core>",
      actionUrl: "https://sigsignature.com/invite?token=abc&email=test@example.com",
    });

    // Angle brackets and quotes must be HTML escaped
    assert.ok(!rendered.includes("<script>"));
    assert.ok(rendered.includes("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"));
    assert.ok(rendered.includes("R&amp;D &quot;VIP&quot; &lt;Core&gt;"));
    assert.ok(rendered.includes("href=\"https://sigsignature.com/invite?token=abc&amp;email=test@example.com\""));
  });
});
