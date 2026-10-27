const { accountService } = require("../services/account.service");
const { clearAuthCookies } = require("../utils/cookies");

const accountController = {
  /**
   * GET /api/v1/account
   * Return user profile, hasPassword, linked oauth providers, settings, and usage.
   */
  async getAccount(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const accountData = await accountService.getAccount(userId);

      return res.status(200).json({
        success: true,
        data: accountData,
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/account
   * Update profile fields (firstName, lastName, companyName).
   */
  async updateProfile(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const updatedUser = await accountService.updateProfile(userId, req.body);

      return res.status(200).json({
        success: true,
        message: "Profile updated successfully",
        data: {
          user: updatedUser,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/account/settings
   * Upsert signature and notification settings.
   */
  async updateSettings(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const settings = await accountService.updateSettings(userId, req.body);

      return res.status(200).json({
        success: true,
        message: "Settings updated successfully",
        data: {
          settings,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/account/waitlist
   * Sets premiumWaitlistAt to now if empty (idempotent).
   */
  async joinWaitlist(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const settings = await accountService.joinWaitlist(userId);

      return res.status(200).json({
        success: true,
        message: "Joined premium waitlist successfully",
        data: {
          settings,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/account/onboarding-seen
   * Mark onboarding as seen for this user.
   */
  async markOnboardingSeen(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const result = await accountService.markOnboardingSeen(userId);

      return res.status(200).json({
        success: true,
        message: "Onboarding marked as seen",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/account/password
   * Change account password and revoke other sessions.
   */
  async changePassword(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const result = await accountService.changePassword(userId, req.body, req);

      return res.status(200).json({
        success: true,
        message: result.message || "Password changed successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/account/export
   * Export account data as JSON attachment with no cache and no secrets.
   */
  async exportAccount(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const exportData = await accountService.exportAccount(userId);

      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        'attachment; filename="sigsignature-account-export.json"'
      );
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
      res.setHeader("Pragma", "no-cache");

      return res.status(200).send(JSON.stringify(exportData, null, 2));
    } catch (error) {
      next(error);
    }
  },

  /**
   * DELETE /api/v1/account
   * Permanently delete user and all owned resources. Clears cookies and returns 204.
   */
  async deleteAccount(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      await accountService.deleteAccount(userId, req.body);
      clearAuthCookies(res);

      return res.status(204).end();
    } catch (error) {
      next(error);
    }
  },
};

module.exports = accountController;
