const crypto = require("crypto");
const { Temporal } = require("@js-temporal/polyfill");
const teamRepository = require("../repositories/team.repository");
const signatureRepository = require("../repositories/signature.repository");
const userRepository = require("../repositories/user.repository");
const mailService = require("./mail.service");
const {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
  TooManyRequestsError,
  GoneError,
  BadGatewayError,
} = require("../utils/errors");

/**
 * Checks whether a team design has actual signature content
 */
function hasSignatureContent(team) {
  if (!team || !team.data || typeof team.data !== "object") return false;
  const d = team.data;
  if (Array.isArray(d.elements) && d.elements.length > 0) return true;
  if (d.name?.trim() || d.title?.trim() || d.company?.trim() || d.email?.trim() || d.phone?.trim()) return true;
  if (Array.isArray(d.extras) && d.extras.length > 0) return true;
  return false;
}

/**
 * Masks an email address for public responses (e.g. z***@gmail.com)
 */
function maskEmail(email) {
  if (!email || typeof email !== "string" || !email.includes("@")) return "";
  const [local, domain] = email.split("@");
  if (!local) return `***@${domain || ""}`;
  return `${local[0]}***@${domain}`;
}

const teamService = {
  /**
   * Get team owned by user with its members ordered by createdAt ascending.
   * Returns null if user does not have a team.
   */
  async getByOwner(userId) {
    return teamRepository.getWithMembersByOwner(userId);
  },

  /**
   * Create a team from an existing signature snapshot.
   * Loads signature, validates ownership, checks team uniqueness,
   * creates the team with a deep copy of data and default memberLimit.
   * Original signature remains untouched.
   */
  async createFromSignature(userId, { signatureId, name }) {
    const signature = await signatureRepository.findByIdForUser(signatureId, userId);
    if (!signature) {
      throw new NotFoundError("Signature not found", "SIGNATURE_NOT_FOUND");
    }

    const existingTeam = await teamRepository.findByOwner(userId);
    if (existingTeam) {
      throw new ConflictError("User already has a team", "TEAM_EXISTS");
    }

    const memberLimit = Number(process.env.TEAM_MEMBER_LIMIT_FREE || 3);
    const kind = signature.templateId === "design-studio" ? "studio" : "template";
    const teamName = name && name.trim() ? name.trim() : signature.name;
    const snapshotData = JSON.parse(JSON.stringify(signature.data));

    const team = await teamRepository.createTeam({
      ownerId: userId,
      name: teamName,
      kind,
      templateId: signature.templateId,
      templateVersion: signature.templateVersion,
      data: snapshotData,
      memberLimit,
    });

    return {
      ...team,
      members: [],
    };
  },

  /**
   * Update team name and/or data.
   * Throws 404 TEAM_NOT_FOUND if user has no team.
   */
  async updateTeam(userId, patch) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    const updatePayload = {};
    if (patch.name !== undefined) {
      updatePayload.name = patch.name.trim();
    }
    if (patch.data !== undefined) {
      const existingData = (team.data && typeof team.data === "object") ? team.data : {};
      const incomingData = (patch.data && typeof patch.data === "object") ? patch.data : {};
      const mergedData = { ...incomingData };

      const existingLifetime = Number(existingData.lifetimeMemberCount || 0);
      const incomingLifetime = Number(incomingData.lifetimeMemberCount || 0);
      if (existingLifetime > 0 || incomingLifetime > 0) {
        mergedData.lifetimeMemberCount = Math.max(existingLifetime, incomingLifetime);
      }

      // Strictly lock companyName and company if already set on the team template
      if (existingData.companyName && typeof existingData.companyName === "string" && existingData.companyName.trim()) {
        mergedData.companyName = existingData.companyName;
      }
      if (existingData.company && typeof existingData.company === "string" && existingData.company.trim()) {
        mergedData.company = existingData.company;
      }

      updatePayload.data = mergedData;
    }

    await teamRepository.updateTeam(team.id, updatePayload);
    return teamRepository.getWithMembersByOwner(userId);
  },

  /**
   * Delete team and cascade delete its members.
   * Throws 404 TEAM_NOT_FOUND if user has no team.
   */
  async deleteTeam(userId) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    await teamRepository.deleteTeam(team.id);
    return true;
  },

  /**
   * Add a member to the user's team.
   * Enforces memberLimit and unique email within the team.
   */
  async addMember(userId, input) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    const currentMemberCount = await teamRepository.countMembers(team.id);
    const teamData = (team.data && typeof team.data === "object") ? team.data : {};
    const lifetimeCount = Math.max(Number(teamData.lifetimeMemberCount || 0), currentMemberCount);

    if (lifetimeCount >= team.memberLimit) {
      throw new ForbiddenError(
        `You have reached the maximum limit of ${team.memberLimit} team members allowed on your plan. Deleting members does not grant additional creation slots. Please upgrade your plan.`,
        "TEAM_MEMBER_LIMIT_REACHED"
      );
    }

    const email = input.email.trim().toLowerCase();
    const existingMember = await teamRepository.findMemberByTeamAndEmail(team.id, email);
    if (existingMember) {
      throw new ConflictError(
        "A team member with this email already exists in your team",
        "TEAM_MEMBER_EXISTS"
      );
    }

    const member = await teamRepository.createMember({
      teamId: team.id,
      name: input.name.trim(),
      email,
      jobTitle: input.jobTitle !== undefined ? input.jobTitle.trim() : "",
      phone: input.phone !== undefined ? input.phone.trim() : "",
      photoUrl: input.photoUrl !== undefined ? input.photoUrl.trim() : "",
      socials: Array.isArray(input.socials) ? input.socials : [],
      status: "draft",
    });

    // Record lifetime team member creation
    const nextLifetime = lifetimeCount + 1;
    await teamRepository.updateTeam(team.id, {
      data: {
        ...teamData,
        lifetimeMemberCount: nextLifetime,
      },
    });

    return member;
  },

  /**
   * Update an existing team member.
   * Scoped strictly through the user's own team.
   * If email is changed after status is sent or accepted, reset status to draft
   * and clear tokenHash, tokenExpiresAt, sentAt and acceptedAt.
   */
  async updateMember(userId, memberId, input) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    const member = await teamRepository.findMemberById(memberId);
    if (!member || member.teamId !== team.id) {
      throw new NotFoundError("Team member not found", "TEAM_MEMBER_NOT_FOUND");
    }

    const updatePayload = {};
    // Full Name Lock: Strictly lock Full Name on existing team members
    if (member.name && member.name.trim()) {
      updatePayload.name = member.name;
    } else if (input.name !== undefined) {
      updatePayload.name = input.name.trim();
    }
    if (input.jobTitle !== undefined) {
      updatePayload.jobTitle = input.jobTitle.trim();
    }
    if (input.phone !== undefined) {
      updatePayload.phone = input.phone.trim();
    }
    if (input.photoUrl !== undefined) {
      updatePayload.photoUrl = input.photoUrl.trim();
    }
    if (input.socials !== undefined) {
      updatePayload.socials = Array.isArray(input.socials) ? input.socials : [];
    }

    if (input.email !== undefined) {
      const newEmail = input.email.trim().toLowerCase();
      if (newEmail !== member.email) {
        const duplicate = await teamRepository.findMemberByTeamAndEmail(team.id, newEmail);
        if (duplicate && duplicate.id !== memberId) {
          throw new ConflictError(
            "A team member with this email already exists in your team",
            "TEAM_MEMBER_EXISTS"
          );
        }

        updatePayload.email = newEmail;
        if (member.status === "sent" || member.status === "accepted") {
          updatePayload.status = "draft";
          updatePayload.tokenHash = null;
          updatePayload.tokenExpiresAt = null;
          updatePayload.sentAt = null;
          updatePayload.acceptedAt = null;
        }
      }
    }

    return teamRepository.updateMember(memberId, updatePayload);
  },

  /**
   * Remove a member from the user's team.
   * Scoped strictly through the user's own team.
   */
  async removeMember(userId, memberId) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    const member = await teamRepository.findMemberById(memberId);
    if (!member || member.teamId !== team.id) {
      throw new NotFoundError("Team member not found", "TEAM_MEMBER_NOT_FOUND");
    }

    // Pin lifetime count before deletion so removing members never restores creation slots
    const currentMemberCount = await teamRepository.countMembers(team.id);
    const teamData = (team.data && typeof team.data === "object") ? team.data : {};
    const existingLifetime = Number(teamData.lifetimeMemberCount || 0);
    const pinnedLifetime = Math.max(existingLifetime, currentMemberCount);

    if (pinnedLifetime > existingLifetime) {
      await teamRepository.updateTeam(team.id, {
        data: {
          ...teamData,
          lifetimeMemberCount: pinnedLifetime,
        },
      });
    }

    await teamRepository.deleteMember(memberId);
    return true;
  },

  /**
   * Send or resend an email invite to a team member.
   * Generates a secure raw token, hashes it, checks rate limits,
   * sends the email, and updates the member status to "sent".
   */
  async sendInvite(userId, memberId) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    const member = await teamRepository.findMemberById(memberId);
    if (!member || member.teamId !== team.id) {
      throw new NotFoundError("Team member not found", "TEAM_MEMBER_NOT_FOUND");
    }

    if (!hasSignatureContent(team)) {
      throw new BadRequestError(
        "Team signature template has no content. Please add signature details before sending invites.",
        "TEAM_NOT_READY"
      );
    }

    // Abuse limit: Cooldown
    const cooldownSeconds = Number(process.env.TEAM_SEND_COOLDOWN_SECONDS || 60);
    if (member.sentAt) {
      const sentAtMs = new Date(member.sentAt.toString()).getTime();
      const elapsedSeconds = Math.floor((Date.now() - sentAtMs) / 1000);
      if (elapsedSeconds < cooldownSeconds) {
        const waitSeconds = cooldownSeconds - elapsedSeconds;
        throw new TooManyRequestsError(
          `Please wait ${waitSeconds} seconds before resending an invite to this member.`,
          "TEAM_SEND_COOLDOWN"
        );
      }
    }

    // Abuse limit: Max sends per member
    const maxPerMember = Number(process.env.TEAM_SEND_MAX_PER_MEMBER || 5);
    if ((member.sendCount || 0) >= maxPerMember) {
      throw new ForbiddenError(
        `Maximum invite send limit reached for this member (${maxPerMember} sends).`,
        "TEAM_SEND_LIMIT_REACHED"
      );
    }

    // Abuse limit: Daily send limit across team in last 24 hours
    const dailyLimit = Number(process.env.TEAM_SEND_DAILY_LIMIT || 10);
    const allMembers = await teamRepository.findMembersByTeam(team.id);
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const recentSends = allMembers.filter((m) => {
      if (!m.sentAt) return false;
      return new Date(m.sentAt.toString()).getTime() >= oneDayAgo;
    });
    if (recentSends.length >= dailyLimit) {
      throw new TooManyRequestsError(
        `Daily team invite limit reached (${dailyLimit} invites per 24 hours). Please try again tomorrow.`,
        "TEAM_SEND_DAILY_LIMIT"
      );
    }

    // Token creation
    const rawToken = crypto.randomBytes(32).toString("base64url");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const ttlDays = Number(process.env.TEAM_INVITE_TTL_DAYS || 14);
    const tokenExpiresAt = Temporal.Now.instant().add({ hours: ttlDays * 24 });
    const frontendBase = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/+$/, "");
    const actionUrl = `${frontendBase}/s/${rawToken}`;

    // Get owner display name
    const user = await userRepository.findFirst({ id: userId });
    const ownerName = [user?.firstName, user?.lastName].filter(Boolean).join(" ").trim() || "Team Admin";

    // Handle suppressed mail mode
    if (process.env.MAIL_ENABLED !== "true") {
      if (process.env.NODE_ENV === "production") {
        return {
          delivered: false,
          suppressed: true,
          member,
        };
      }

      // In non-production (dev/test): update member so invite flow can be tested locally
      const updatedMember = await teamRepository.updateMember(member.id, {
        status: "sent",
        sentAt: Temporal.Now.instant(),
        sendCount: (member.sendCount || 0) + 1,
        tokenHash,
        tokenExpiresAt,
      });

      return {
        delivered: false,
        suppressed: true,
        devInviteUrl: actionUrl,
        member: updatedMember,
      };
    }

    // Mail enabled: attempt delivery via SES
    try {
      await mailService.sendTeamInviteEmail({
        to: member.email,
        memberName: member.name,
        ownerName,
        teamName: team.name,
        actionUrl,
        expiresIn: `${ttlDays} days`,
      });
    } catch (err) {
      console.error("[Team Service] Error sending team invite email via SES:", err.name, err.message);
      // If sending fails (e.g. SES MessageRejected or sandbox unverified):
      // do NOT change the member, and return 502 with code TEAM_EMAIL_REJECTED
      throw new BadGatewayError(
        "The email could not be delivered. While email sending is in test mode only verified addresses can receive messages.",
        "TEAM_EMAIL_REJECTED"
      );
    }

    // Only after email is sent successfully:
    const updatedMember = await teamRepository.updateMember(member.id, {
      status: "sent",
      sentAt: Temporal.Now.instant(),
      sendCount: (member.sendCount || 0) + 1,
      tokenHash,
      tokenExpiresAt,
    });

    return {
      delivered: true,
      member: updatedMember,
    };
  },

  /**
   * Revoke an active invite for a team member.
   * Sets status to "revoked" and keeps tokenHash so public endpoints return 410.
   */
  async revokeInvite(userId, memberId) {
    const team = await teamRepository.findByOwner(userId);
    if (!team) {
      throw new NotFoundError("Team not found", "TEAM_NOT_FOUND");
    }

    const member = await teamRepository.findMemberById(memberId);
    if (!member || member.teamId !== team.id) {
      throw new NotFoundError("Team member not found", "TEAM_MEMBER_NOT_FOUND");
    }

    const updatedMember = await teamRepository.updateMember(member.id, {
      status: "revoked",
    });

    return updatedMember;
  },

  /**
   * Look up public invite details by raw invite token.
   * Unknown token: 404 INVITE_NOT_FOUND
   * Revoked token: 410 INVITE_REVOKED
   * Sent & expired token: 410 INVITE_EXPIRED
   * Draft member: 404 INVITE_NOT_FOUND
   * Accepted members retain access even after expiration date.
   */
  async getPublicInvite(rawToken) {
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const member = await teamRepository.findMemberByTokenHash(tokenHash);
    if (!member) {
      throw new NotFoundError("Invite not found or invalid link.", "INVITE_NOT_FOUND");
    }

    const team = await teamRepository.findTeamById(member.teamId);
    if (!team) {
      throw new NotFoundError("Invite not found or invalid link.", "INVITE_NOT_FOUND");
    }

    if (member.status === "revoked") {
      throw new GoneError("This invite has been revoked by the team owner.", "INVITE_REVOKED");
    }

    if (member.status === "draft") {
      throw new NotFoundError("Invite not found or invalid link.", "INVITE_NOT_FOUND");
    }

    // If status is "sent" and expired: 410 INVITE_EXPIRED
    if (member.status === "sent" && member.tokenExpiresAt) {
      const expiresAtDate = new Date(member.tokenExpiresAt.toString());
      if (expiresAtDate.getTime() <= Date.now()) {
        throw new GoneError(
          "This invite link has expired. Please request a new invite from the team owner.",
          "INVITE_EXPIRED"
        );
      }
    }

    return {
      member: {
        name: member.name,
        maskedEmail: maskEmail(member.email),
        jobTitle: member.jobTitle || "",
        phone: member.phone || "",
        photoUrl: member.photoUrl || "",
        socials: Array.isArray(member.socials) ? member.socials : [],
        status: member.status,
      },
      team: {
        name: team.name,
        kind: team.kind,
        templateId: team.templateId,
        templateVersion: team.templateVersion,
        data: team.data,
      },
      expiresAt: member.tokenExpiresAt
        ? (typeof member.tokenExpiresAt.toISOString === "function" ? member.tokenExpiresAt.toISOString() : String(member.tokenExpiresAt))
        : null,
    };
  },

  /**
   * Accept an invite by raw token.
   * If status is "sent", sets status "accepted" and acceptedAt = now.
   * If already accepted, returns same success (idempotent).
   * Draft members cannot be accepted (404).
   */
  async acceptPublicInvite(rawToken) {
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const member = await teamRepository.findMemberByTokenHash(tokenHash);
    if (!member) {
      throw new NotFoundError("Invite not found or invalid link.", "INVITE_NOT_FOUND");
    }

    const team = await teamRepository.findTeamById(member.teamId);
    if (!team) {
      throw new NotFoundError("Invite not found or invalid link.", "INVITE_NOT_FOUND");
    }

    if (member.status === "revoked") {
      throw new GoneError("This invite has been revoked by the team owner.", "INVITE_REVOKED");
    }

    if (member.status === "draft") {
      throw new NotFoundError("Invite not found or invalid link.", "INVITE_NOT_FOUND");
    }

    if (member.status === "sent") {
      if (member.tokenExpiresAt) {
        const expiresAtDate = new Date(member.tokenExpiresAt.toString());
        if (expiresAtDate.getTime() <= Date.now()) {
          throw new GoneError(
            "This invite link has expired. Please request a new invite from the team owner.",
            "INVITE_EXPIRED"
          );
        }
      }

      const acceptedAt = Temporal.Now.instant();
      const updatedMember = await teamRepository.updateMember(member.id, {
        status: "accepted",
        acceptedAt,
      });

      return {
        member: {
          name: updatedMember.name,
          maskedEmail: maskEmail(updatedMember.email),
          jobTitle: updatedMember.jobTitle || "",
          phone: updatedMember.phone || "",
          photoUrl: updatedMember.photoUrl || "",
          socials: Array.isArray(updatedMember.socials) ? updatedMember.socials : [],
          status: "accepted",
        },
        team: {
          name: team.name,
          kind: team.kind,
          templateId: team.templateId,
          templateVersion: team.templateVersion,
          data: team.data,
        },
        acceptedAt: acceptedAt.toString(),
      };
    }

    // Already accepted (idempotent)
    return {
      member: {
        name: member.name,
        maskedEmail: maskEmail(member.email),
        jobTitle: member.jobTitle || "",
        phone: member.phone || "",
        photoUrl: member.photoUrl || "",
        socials: Array.isArray(member.socials) ? member.socials : [],
        status: "accepted",
      },
      team: {
        name: team.name,
        kind: team.kind,
        templateId: team.templateId,
        templateVersion: team.templateVersion,
        data: team.data,
      },
      acceptedAt: member.acceptedAt
        ? (typeof member.acceptedAt.toISOString === "function" ? member.acceptedAt.toISOString() : String(member.acceptedAt))
        : new Date().toISOString(),
    };
  },
};

module.exports = teamService;
