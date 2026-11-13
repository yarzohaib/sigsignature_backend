const integrationService = require("../services/integration.service");
const oauthService = require("../services/oauth.service");

function getUser(req) {
  return { userId: req.user.id || req.user.sub, email: req.user.email };
}

const integrationController = {
  /** GET /api/v1/integrations/gmail */
  async gmailStatus(req, res, next) {
    try {
      const { userId } = getUser(req);
      const status = await integrationService.getGmailStatus(userId);
      return res.status(200).json({ success: true, data: status });
    } catch (error) {
      next(error);
    }
  },

  /** POST /api/v1/integrations/gmail/connect  ->  { url } to send the browser to Google */
  async gmailConnect(req, res, next) {
    try {
      const { userId, email } = getUser(req);
      const result = await integrationService.startGmailConnect({
        userId,
        email,
        frontendOrigin: req.body?.frontendOrigin,
        req,
      });
      return res.status(200).json({ success: true, data: result });
    } catch (error) {
      next(error);
    }
  },

  /** GET /api/v1/integrations/gmail/callback  (public: Google redirects the browser here) */
  async gmailCallback(req, res) {
    let target;
    try {
      const { code, state, error } = req.query;
      target = await integrationService.completeGmailConnect({
        code: typeof code === "string" ? code : undefined,
        state: typeof state === "string" ? state : undefined,
        error: typeof error === "string" ? error : undefined,
        req,
      });
    } catch (err) {
      console.error("[gmail callback] unexpected error:", err.message);
      target = `${oauthService.getFrontendUrl()}/settings?integration=gmail&status=error&reason=failed`;
    }
    res.setHeader("Cache-Control", "no-store");
    return res.redirect(302, target);
  },

  /** POST /api/v1/integrations/gmail/push */
  async gmailPush(req, res, next) {
    try {
      const { userId } = getUser(req);
      const result = await integrationService.pushGmailSignature({
        userId,
        signatureId: req.body.signatureId,
        html: req.body.html,
      });
      return res.status(200).json({ success: true, data: result });
    } catch (error) {
      next(error);
    }
  },

  /** DELETE /api/v1/integrations/gmail */
  async gmailDisconnect(req, res, next) {
    try {
      const { userId } = getUser(req);
      const result = await integrationService.disconnectGmail(userId);
      return res.status(200).json({ success: true, data: result });
    } catch (error) {
      next(error);
    }
  },
};

module.exports = integrationController;
