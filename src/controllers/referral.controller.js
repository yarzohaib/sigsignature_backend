const referralService = require("../services/referral.service");

const referralController = {
  /**
   * GET /api/v1/referrals
   * Returns current user's referral link, code, count, and pro trial status.
   */
  async getReferralInfo(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const data = await referralService.getReferralInfo(userId);
      res.status(200).json({
        success: true,
        data,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/referrals/invite
   * Sends 1-click email invitation to a colleague with embedded referral link.
   */
  async sendInvite(req, res, next) {
    try {
      const userId = req.user.id || req.user.sub;
      const { email } = req.body;
      const result = await referralService.sendInvite(userId, email);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = referralController;
