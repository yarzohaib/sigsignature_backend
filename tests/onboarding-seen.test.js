const { test, describe } = require("node:test");
const assert = require("node:assert/strict");

const { accountService } = require("../src/services/account.service");
const userRepository = require("../src/repositories/user.repository");
const accountController = require("../src/controllers/account.controller");

describe("BUG-API-01: POST /api/v1/account/onboarding-seen Suite", () => {
  let testUserId = null;

  test("0. Setup test user", async () => {
    const users = await userRepository.findAll();
    assert.ok(users && users.length > 0, "Database must have at least one test user");
    testUserId = users[0].id;
  });

  test("1. userRepository.markOnboardingSeen updates onboardingSeenAt via pool.query and returns updated user", async () => {
    assert.ok(testUserId, "testUserId must be populated");
    const updated = await userRepository.markOnboardingSeen(testUserId);
    assert.ok(updated, "Updated user must be returned");
    assert.equal(updated.id, testUserId, "Updated user ID must match");
    assert.ok(updated.onboardingSeenAt, "onboardingSeenAt must be populated");
    const ts = new Date(updated.onboardingSeenAt).getTime();
    assert.ok(!isNaN(ts), "onboardingSeenAt must be a valid date/timestamp");
  });

  test("2. accountService.markOnboardingSeen returns ISO formatted onboardingSeenAt envelope", async () => {
    assert.ok(testUserId, "testUserId must be populated");
    const res = await accountService.markOnboardingSeen(testUserId);
    assert.ok(res, "Result must be returned");
    assert.ok(res.onboardingSeenAt, "onboardingSeenAt must be returned");
    assert.match(
      res.onboardingSeenAt,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
      "onboardingSeenAt must be an ISO timestamp"
    );
  });

  test("3. accountController.markOnboardingSeen handles sub/id and returns 200 JSON envelope", async () => {
    const req = {
      user: {
        id: testUserId,
        sub: testUserId,
      },
    };

    let statusCode = null;
    let responseBody = null;

    const res = {
      status(code) {
        statusCode = code;
        return this;
      },
      json(data) {
        responseBody = data;
        return this;
      },
    };

    let errorPassed = null;
    const next = (err) => {
      errorPassed = err;
    };

    await accountController.markOnboardingSeen(req, res, next);

    assert.equal(errorPassed, null, "No error should be passed to next()");
    assert.equal(statusCode, 200, "HTTP Status must be 200 OK");
    assert.equal(responseBody.success, true, "Envelope must have success: true");
    assert.equal(responseBody.message, "Onboarding marked as seen");
    assert.ok(responseBody.data?.onboardingSeenAt, "data.onboardingSeenAt must be populated");
  });
});
