const express = require("express");
const referralController = require("../controllers/referral.controller");
const { authenticate } = require("../middleware/auth.middleware");

const router = express.Router();

router.get("/", authenticate, referralController.getReferralInfo);
router.post("/invite", authenticate, referralController.sendInvite);

module.exports = router;
