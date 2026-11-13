const authService = require("../services/auth.service");
const { setAuthCookies, clearAuthCookies } = require("../utils/cookies");
const { AppError, BadRequestError } = require("../utils/errors");

const authController = {
  async signup(req, res, next) {
    try {
      const { email, password, firstName, lastName, referralCode } = req.body;

      if (!firstName || !firstName.trim()) {
        throw new BadRequestError("First name is required");
      }

      if (!email || !email.trim()) {
        throw new BadRequestError("Email is required");
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email.trim())) {
        throw new BadRequestError("Please provide a valid email address");
      }

      if (!password || password.length < 6) {
        throw new BadRequestError("Password must be at least 6 characters long");
      }

      const user = await authService.signup({
        email: email.trim(),
        password,
        firstName: firstName.trim(),
        lastName: lastName ? lastName.trim() : null,
        referralCode: referralCode ? referralCode.trim() : null,
      });

      return res.status(201).json({
        success: true,
        message: "User created successfully",
        data: {
          user,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  async me(req, res, next) {
    try {
      const user = await authService.getCurrentUser(req.user.sub);

      if (!user) {
        throw new NotFoundError("User not found");
      }

      return res.status(200).json({
        success: true,
        data: {
          user,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  async login(req, res, next) {
    try {
      const { email, password } = req.body;

      if (!email || !email.trim()) {
        throw new BadRequestError("Email is required");
      }

      if (!password) {
        throw new BadRequestError("Password is required");
      }

      const result = await authService.login(
        {
          email: email.trim(),
          password,
        },
        {
          userAgent: req.headers["user-agent"],
          ipAddress: req.ip,
        }
      );

      // Set HttpOnly cookies on the response
      setAuthCookies(res, result.tokens);

      return res.status(200).json({
        success: true,
        message: "Login successful",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  },

  async refresh(req, res, next) {
    try {
      // Support HttpOnly cookie or request body
      const refreshToken = req.cookies?.refresh_token || req.body?.refreshToken;

      if (!refreshToken) {
        throw new BadRequestError("Refresh token is required");
      }

      const result = await authService.refreshTokens(refreshToken, {
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
      });

      // Update HttpOnly cookies
      setAuthCookies(res, {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });

      return res.status(200).json({
        success: true,
        message: "Token refreshed successfully",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  },

  async logout(req, res, next) {
    try {
      const refreshToken = req.cookies?.refresh_token || req.body?.refreshToken;

      if (refreshToken) {
        try {
          await authService.logout(refreshToken);
        } catch (_) {
          // Ignore invalid token on logout so client always clears cookies
        }
      }

      clearAuthCookies(res);

      return res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  async logoutAll(req, res, next) {
    try {
      await authService.logoutAll(req.user.sub);
      clearAuthCookies(res);

      return res.status(200).json({
        success: true,
        message: "Logged out from all sessions",
      });
    } catch (error) {
      next(error);
    }
  },

  async sessions(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const sessions = await authService.getSessions(userId, req);

      return res.status(200).json({
        success: true,
        data: {
          sessions,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  async revokeSession(req, res, next) {
    try {
      const { id } = req.params;
      const userId = req.user.sub || req.user.id;
      await authService.revokeSession(userId, id);

      return res.status(200).json({
        success: true,
        message: "Session revoked successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  async revokeOtherSessions(req, res, next) {
    try {
      const userId = req.user.sub || req.user.id;
      const result = await authService.revokeOtherSessions(userId, req);

      return res.status(200).json({
        success: true,
        message: "Other sessions revoked successfully",
        count: result.count,
        revokedCount: result.count,
      });
    } catch (error) {
      next(error);
    }
  },

  async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;

      if (!email || !email.trim()) {
        throw new BadRequestError("Email is required");
      }

      await authService.forgotPassword(email.trim());

      return res.status(200).json({
        success: true,
        message:
          "If an account exists for this email, a password reset link has been generated",
      });
    } catch (error) {
      next(error);
    }
  },

  async validateResetToken(req, res, next) {
    try {
      const token = req.query.token || req.body?.token;

      if (!token) {
        throw new BadRequestError("Token is required");
      }

      const result = await authService.validateResetToken(token.trim());

      return res.status(200).json({
        success: true,
        valid: result.valid,
        message: "Reset token is valid",
      });
    } catch (error) {
      next(error);
    }
  },

  async resetPassword(req, res, next) {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        throw new BadRequestError("Token and new password are required");
      }

      await authService.resetPassword(token.trim(), newPassword);

      return res.status(200).json({
        success: true,
        message: "Password reset successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  async requestVerification(req, res, next) {
    try {
      const { email } = req.body;

      if (!email || !email.trim()) {
        throw new BadRequestError("Email is required");
      }

      const result = await authService.requestEmailVerification(email.trim());
      return res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  },

  async verifyEmail(req, res, next) {
    try {
      const { token } = req.body;

      if (!token || !token.trim()) {
        throw new BadRequestError("Verification token is required");
      }

      const result = await authService.verifyEmailToken(token.trim());
      return res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  },
};

module.exports = authController;