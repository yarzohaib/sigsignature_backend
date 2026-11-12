const crypto = require("crypto");
const userRepository = require("../repositories/user.repository");
const mailService = require("./mail.service");
const { BadRequestError, NotFoundError } = require("../utils/errors");

function generateReferralCode() {
  return "SIG" + crypto.randomBytes(3).toString("hex").toUpperCase();
}

const referralService = {
  /**
   * Get or create current user's personal referral link and stats.
   */
  async getReferralInfo(userId) {
    let user = await userRepository.findFirst({ id: userId });
    if (!user) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    let referralCode = user.referralCode;
    if (!referralCode) {
      referralCode = generateReferralCode();
      await userRepository.setReferralCode(user.id, referralCode);
    }

    let frontendBase = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
    if (frontendBase.startsWith("https://localhost")) {
      frontendBase = frontendBase.replace("https://", "http://");
    }
    const shareUrl = `${frontendBase}/signup?ref=${referralCode}`;

    const isProTrialActive = Boolean(
      user.proTrialUntil && new Date(user.proTrialUntil).getTime() > Date.now()
    );

    return {
      referralCode,
      shareUrl,
      referralCount: user.referralCount || 0,
      proTrialUntil: user.proTrialUntil ? user.proTrialUntil.toISOString?.() || String(user.proTrialUntil) : null,
      isProTrialActive,
    };
  },

  /**
   * Send 1-click email invitation to a friend/colleague.
   */
  async sendInvite(userId, recipientEmail) {
    if (!recipientEmail || typeof recipientEmail !== "string") {
      throw new BadRequestError("Recipient email address is required");
    }

    const normalizedRecipient = recipientEmail.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedRecipient)) {
      throw new BadRequestError("Please provide a valid email address");
    }

    const sender = await userRepository.findFirst({ id: userId });
    if (!sender) {
      throw new NotFoundError("User not found", "USER_NOT_FOUND");
    }

    // Anti-abuse: Prevent self-referrals
    if (sender.email.toLowerCase() === normalizedRecipient) {
      throw new BadRequestError("You cannot invite your own email address");
    }

    // Strip +tags for Gmail/Outlook to prevent self-referral aliasing (e.g. user+1@gmail.com)
    const [senderUser, senderDomain] = sender.email.toLowerCase().split("@");
    const [recipientUser, recipientDomain] = normalizedRecipient.split("@");
    const senderBase = senderUser.split("+")[0];
    const recipientBase = recipientUser.split("+")[0];
    if (senderDomain === recipientDomain && senderBase === recipientBase) {
      throw new BadRequestError("You cannot invite an alias of your own email address");
    }

    // Ensure sender has a unique referralCode
    let referralCode = sender.referralCode;
    if (!referralCode) {
      referralCode = generateReferralCode();
      await userRepository.setReferralCode(sender.id, referralCode);
    }

    let frontendBase = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
    if (frontendBase.startsWith("https://localhost")) {
      frontendBase = frontendBase.replace("https://", "http://");
    }
    const inviteUrl = `${frontendBase}/signup?ref=${referralCode}&email=${encodeURIComponent(normalizedRecipient)}`;
    const senderName = `${sender.firstName || ""} ${sender.lastName || ""}`.trim() || "A colleague";

    await mailService.sendReferralInviteEmail({
      to: normalizedRecipient,
      senderName,
      inviteUrl,
    });

    return {
      success: true,
      message: `Invitation successfully sent to ${normalizedRecipient}`,
    };
  },

  /**
   * Validates a referral code and attaches referredById to a new user.
   */
  async processReferralOnSignup(newUserId, referralCode, newEmail) {
    if (!referralCode || !newUserId) return null;
    const inviter = await userRepository.findByReferralCode(referralCode);
    if (!inviter || inviter.id === newUserId) return null;

    // Prevent aliased self-referrals
    if (newEmail && inviter.email) {
      const [inviterUser, inviterDomain] = inviter.email.toLowerCase().split("@");
      const [newUserPart, newDomain] = newEmail.toLowerCase().split("@");
      if (inviterDomain === newDomain && inviterUser.split("+")[0] === newUserPart.split("+")[0]) {
        console.warn(`[Referral] Blocked aliased self-referral between ${inviter.email} and ${newEmail}`);
        return null;
      }
    }

    await userRepository.setReferredBy(newUserId, inviter.id);
    return inviter;
  },

  /**
   * Unlocks 30 Days of Pro for the inviter immediately without credit card.
   * Triggered upon email verification or Google OAuth registration of the invitee.
   */
  async activateReferralRewards(inviteeId) {
    const invitee = await userRepository.findFirst({ id: inviteeId });
    if (!invitee || !invitee.referredById) {
      return null;
    }

    const inviter = await userRepository.findFirst({ id: invitee.referredById });
    if (!inviter) {
      return null;
    }

    // 1. Grant 30 days to inviter only
    const updatedInviter = await userRepository.grantProTrialDays(inviter.id, 30);

    // 2. Send celebration notification email to inviter
    try {
      const inviteeName = `${invitee.firstName || ""} ${invitee.lastName || ""}`.trim() || invitee.email;
      const proTrialDate = updatedInviter?.proTrialUntil
        ? new Date(updatedInviter.proTrialUntil).toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
          })
        : "30 days";

      mailService
        .sendReferralRewardUnlockedEmail({
          to: inviter.email,
          firstName: inviter.firstName,
          inviteeName,
          proTrialUntil: proTrialDate,
        })
        .catch((err) => {
          console.error("[Referral Service] Failed to send celebration email:", err.message || err);
        });
    } catch (err) {
      console.warn("[Referral Service] Error formulating reward email:", err);
    }

    return {
      inviter: updatedInviter,
      invitee,
    };
  },
  generateReferralCode,
};

module.exports = referralService;
