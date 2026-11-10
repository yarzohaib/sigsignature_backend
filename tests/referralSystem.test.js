const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { Pool } = require("pg");
require("dotenv").config();

// Ensure test emails are suppressed during tests
process.env.MAIL_ENABLED = "false";

const userRepository = require("../src/repositories/user.repository");
const referralService = require("../src/services/referral.service");
const authService = require("../src/services/auth.service");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

describe("Referral System & 1-Month Free Pro Backend Suite", () => {
  const timestamp = Date.now();
  const inviterEmail = `inviter_${timestamp}@example.com`;
  const inviteeEmail = `invitee_${timestamp}@example.com`;

  let inviterUser;
  let inviteeUser;
  let referralCode;

  before(async () => {
    // Create inviter user directly
    inviterUser = await userRepository.create({
      email: inviterEmail,
      firstName: "Inviter",
      lastName: "User",
      isVerified: true,
      isActive: true,
    });
  });

  after(async () => {
    // Cleanup created test users
    await pool.query(
      `DELETE FROM "User" WHERE "email" IN ($1, $2, $3, $4)`,
      [inviterEmail, inviteeEmail, `oauth_${timestamp}@example.com`, `self_${timestamp}@example.com`]
    );
    await pool.end();
  });

  test("1. getReferralInfo generates a unique referralCode and shareUrl for inviter", async () => {
    const info = await referralService.getReferralInfo(inviterUser.id);
    assert.ok(info.referralCode, "Referral code should be generated");
    assert.match(info.referralCode, /^SIG[A-Z0-9]+$/, "Referral code should start with SIG");
    assert.ok(info.shareUrl.includes(info.referralCode), "Share URL should contain referralCode");
    assert.equal(info.referralCount, 0, "Initial referral count should be 0");
    assert.equal(info.isProTrialActive, false, "Initial pro trial should be inactive");

    referralCode = info.referralCode;
  });

  test("2. sendInvite validates recipient email and prevents self-referrals", async () => {
    // Self-referral attempt
    await assert.rejects(
      async () => {
        await referralService.sendInvite(inviterUser.id, inviterEmail);
      },
      /cannot invite your own email address/i,
      "Should reject inviting self"
    );

    // Aliased self-referral attempt (inviter+test@example.com)
    const [name, domain] = inviterEmail.split("@");
    await assert.rejects(
      async () => {
        await referralService.sendInvite(inviterUser.id, `${name}+test@${domain}`);
      },
      /cannot invite an alias of your own email address/i,
      "Should reject aliased self-invitation"
    );

    // Valid invitation
    const inviteResult = await referralService.sendInvite(inviterUser.id, inviteeEmail);
    assert.equal(inviteResult.success, true);
    assert.match(inviteResult.message, /successfully sent/i);
  });

  test("3. Signup with referralCode links referredById to the inviter", async () => {
    // Create new account using authService with referralCode
    const created = await authService.signup({
      email: inviteeEmail,
      password: "Password123!",
      firstName: "Invitee",
      lastName: "Friend",
      referralCode,
    });

    // Query DB row with pg pool to verify referredById was set
    const res = await pool.query(`SELECT * FROM "User" WHERE "id" = $1`, [created.id]);
    inviteeUser = res.rows[0];
    assert.ok(inviteeUser, "Invitee should exist in DB");
    assert.equal(inviteeUser.referredById, inviterUser.id, "Invitee referredById should match inviter.id");
    assert.equal(inviteeUser.isVerified, false, "Email should not be verified yet");
  });

  test("4. Email verification triggers automatic Pro activation for the inviter only", async () => {
    // Before verification: check inviter proTrialUntil is null
    const resBefore = await pool.query(`SELECT * FROM "User" WHERE "id" = $1`, [inviterUser.id]);
    const inviterBefore = resBefore.rows[0];
    assert.equal(inviterBefore.proTrialUntil, null);

    // Activate referral reward
    const rewards = await referralService.activateReferralRewards(inviteeUser.id);
    assert.ok(rewards, "Rewards should be granted");

    // Inviter should have pro trial active for 30 days
    assert.ok(rewards.inviter.proTrialUntil, "Inviter proTrialUntil should be set");
    assert.equal(rewards.inviter.referralCount, 1, "Inviter referralCount should increment to 1");

    const inviterTrialDate = new Date(rewards.inviter.proTrialUntil);
    const expectedDays = Math.round((inviterTrialDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    assert.ok(expectedDays >= 29 && expectedDays <= 31, `Trial duration should be ~30 days, got ${expectedDays}`);

    // Invitee should NOT receive pro trial (only the sender gets the reward)
    const resInviteeAfter = await pool.query(`SELECT * FROM "User" WHERE "id" = $1`, [inviteeUser.id]);
    assert.equal(resInviteeAfter.rows[0].proTrialUntil, null, "Invitee should remain on standard free tier");

    // Verify info endpoint reflects active pro status for inviter
    const inviterInfo = await referralService.getReferralInfo(inviterUser.id);
    assert.equal(inviterInfo.isProTrialActive, true, "Inviter pro trial should now be active");
    assert.equal(inviterInfo.referralCount, 1, "Inviter referral count should be 1");
  });

  test("5. Secondary referral stacks/extends existing pro trial duration", async () => {
    const resBefore = await pool.query(`SELECT * FROM "User" WHERE "id" = $1`, [inviterUser.id]);
    const inviterBefore = resBefore.rows[0];
    const currentExpiry = new Date(inviterBefore.proTrialUntil).getTime();

    // Grant additional 30 days
    const stacked = await userRepository.grantProTrialDays(inviterUser.id, 30);
    const newExpiry = new Date(stacked.proTrialUntil).getTime();

    const extendedDays = Math.round((newExpiry - currentExpiry) / (1000 * 60 * 60 * 24));
    assert.ok(extendedDays >= 29 && extendedDays <= 31, `Expiry should extend by 30 days, got ${extendedDays}`);
    assert.equal(stacked.referralCount, 2, "Referral count should increment to 2");
  });
});
