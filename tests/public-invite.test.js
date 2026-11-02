const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const teamService = require("../src/services/team.service");
const teamRepository = require("../src/repositories/team.repository");

describe("Public Team Invite Suite", () => {
  test("getPublicInvite returns full member email and maskedEmail", async () => {
    const rawToken = "test_invite_token_12345";
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    const mockMember = {
      id: "mem-1",
      teamId: "team-1",
      name: "maryam",
      email: "maruim1677@gmail.com",
      jobTitle: "hr",
      phone: "+1234567890",
      photoUrl: "",
      socials: [],
      status: "sent",
      tokenExpiresAt: new Date(Date.now() + 86400000),
    };

    const mockTeam = {
      id: "team-1",
      name: "Acme Corp",
      kind: "template",
      templateId: "minimal-clean",
      templateVersion: 1,
      data: {},
    };

    const origFindMember = teamRepository.findMemberByTokenHash;
    const origFindTeam = teamRepository.findTeamById;

    try {
      teamRepository.findMemberByTokenHash = async (hash) => {
        if (hash === tokenHash) return mockMember;
        return null;
      };
      teamRepository.findTeamById = async (id) => {
        if (id === "team-1") return mockTeam;
        return null;
      };

      const inviteData = await teamService.getPublicInvite(rawToken);

      assert.ok(inviteData);
      assert.equal(inviteData.member.name, "maryam");
      // Full email must be returned so the signature renders the actual email
      assert.equal(inviteData.member.email, "maruim1677@gmail.com");
      // maskedEmail must also be present
      assert.equal(inviteData.member.maskedEmail, "m***@gmail.com");
    } finally {
      teamRepository.findMemberByTokenHash = origFindMember;
      teamRepository.findTeamById = origFindTeam;
    }
  });

  test("acceptPublicInvite returns full member email and maskedEmail", async () => {
    const rawToken = "test_invite_token_accept";
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    const mockMember = {
      id: "mem-2",
      teamId: "team-2",
      name: "John Doe",
      email: "john.doe@example.com",
      jobTitle: "Developer",
      phone: "+1987654321",
      photoUrl: "",
      socials: [],
      status: "sent",
      tokenExpiresAt: new Date(Date.now() + 86400000),
    };

    const mockTeam = {
      id: "team-2",
      name: "Dev Team",
      kind: "studio",
      templateId: "design-studio",
      templateVersion: 1,
      data: {},
    };

    const origFindMember = teamRepository.findMemberByTokenHash;
    const origFindTeam = teamRepository.findTeamById;
    const origUpdateMember = teamRepository.updateMember;

    try {
      teamRepository.findMemberByTokenHash = async () => mockMember;
      teamRepository.findTeamById = async () => mockTeam;
      teamRepository.updateMember = async (id, patch) => ({
        ...mockMember,
        ...patch,
      });

      const acceptData = await teamService.acceptPublicInvite(rawToken);

      assert.ok(acceptData);
      assert.equal(acceptData.member.name, "John Doe");
      assert.equal(acceptData.member.email, "john.doe@example.com");
      assert.equal(acceptData.member.maskedEmail, "j***@example.com");
      assert.equal(acceptData.member.status, "accepted");
    } finally {
      teamRepository.findMemberByTokenHash = origFindMember;
      teamRepository.findTeamById = origFindTeam;
      teamRepository.updateMember = origUpdateMember;
    }
  });
});
