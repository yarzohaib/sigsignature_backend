require("dotenv").config();
const fs = require('fs');
const path = require('path');
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const TEMPLATES_DIR = path.join(__dirname, '..', 'templates', 'emails');

// Template cache
const templates = {
  emailVerification: null,
  passwordReset: null,
  teamInvite: null,
  securityPasswordChanged: null,
  securitySessionsRevoked: null,
  accountDeleted: null,
};

function getTemplate(name, filename) {
  if (process.env.NODE_ENV !== 'production' || !templates[name]) {
    const filePath = path.join(TEMPLATES_DIR, filename);
    templates[name] = fs.readFileSync(filePath, 'utf8');
  }
  return templates[name];
}

/**
 * Escapes HTML characters in user input to prevent HTML injection in emails
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Replaces {{placeholder}} tokens in email templates
 * Confirms every user supplied value that enters an HTML email goes through escapeHtml.
 * Escapes all variables by default unless explicitly excluded.
 */
function renderTemplate(templateContent, variables = {}, escapeKeys = null) {
  let output = templateContent;
  for (const [key, value] of Object.entries(variables)) {
    const shouldEscape = Array.isArray(escapeKeys) ? escapeKeys.includes(key) : true;
    const formattedValue = shouldEscape ? escapeHtml(value) : String(value ?? '');
    const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
    output = output.replace(placeholder, formattedValue);
  }
  return output;
}

/**
 * Generic email sending function
 * @param {Object} options
 * @param {string} options.to - Recipient email address
 * @param {string} options.subject - Subject line
 * @param {string} options.html - HTML body
 * @param {string} options.text - Plain text body
 */
async function sendEmail({ to, subject, html, text }) {
  if (process.env.MAIL_ENABLED !== "true") {
    console.log(`[Mail Service] Email suppressed. Recipient: ${to}, Subject: "${subject}"`);
    return { success: false, suppressed: true };
  }

  const { data, error } = await resend.emails.send({
    from: process.env.MAIL_FROM,
    to: [to],
    replyTo: process.env.MAIL_REPLY_TO,
    subject,
    html,
    text,
  });

  if (error) {
    console.error(`[Mail Service] Resend error sending to ${to}: ${error.message}`);
    throw new Error(error.message);
  }

  console.log(`[Mail Service] Email sent via Resend. Recipient: ${to}, Id: ${data.id}`);
  return { success: true, messageId: data.id };
}

/**
 * Sends a password reset email with both HTML and plain-text body
 */
async function sendPasswordResetEmail({ to, firstName, actionUrl, expiresIn = '30 minutes' }) {
  const greetingName = firstName || 'there';
  const rawHtml = getTemplate('passwordReset', 'pass_reset.html');
  const html = renderTemplate(rawHtml, {
    firstName: greetingName,
    actionUrl,
    expiresIn,
  });

  const text = [
    `Hi ${greetingName},`,
    '',
    'Need a new password? Use the link below to securely reset your password and regain access to your Sig Signature account:',
    '',
    actionUrl,
    '',
    `This password reset link will expire in ${expiresIn}.`,
    '',
    "If you didn't request this password reset, you can safely ignore this email. Your account will remain secure.",
    '',
    '© 2026 Sig Signature. All rights reserved.',
  ].join('\n');

  return sendEmail({
    to,
    subject: 'Reset your Sig Signature password',
    html,
    text,
  });
}

/**
 * Sends an email verification email with both HTML and plain-text body
 */
async function sendVerificationEmail({ to, firstName, actionUrl, expiresIn = '24 hours' }) {
  const greetingName = firstName || 'there';
  const rawHtml = getTemplate('emailVerification', 'email_verification.html');
  const html = renderTemplate(rawHtml, {
    firstName: greetingName,
    actionUrl,
    expiresIn,
  });

  const text = [
    `Hi ${greetingName},`,
    '',
    'Please verify your email address to activate your account and start creating professional email signatures:',
    '',
    actionUrl,
    '',
    `This verification link will expire in ${expiresIn}.`,
    '',
    "If you didn't create a Sig Signature account, you can safely ignore this email.",
    '',
    '© 2026 Sig Signature. All rights reserved.',
  ].join('\n');

  return sendEmail({
    to,
    subject: 'Confirm your Sig Signature email address',
    html,
    text,
  });
}

/**
 * Sends a team signature invite email with both HTML and plain-text body
 */
async function sendTeamInviteEmail({ to, memberName, ownerName, teamName, actionUrl, expiresIn = '14 days' }) {
  const greetingMemberName = memberName || 'there';
  const displayOwnerName = ownerName || 'Your team admin';
  const displayTeamName = teamName || 'your team';

  const rawHtml = getTemplate('teamInvite', 'team_invite.html');
  const html = renderTemplate(
    rawHtml,
    {
      memberName: greetingMemberName,
      ownerName: displayOwnerName,
      teamName: displayTeamName,
      actionUrl,
      expiresIn,
    }
  );

  const text = [
    `Hi ${greetingMemberName},`,
    '',
    `${displayOwnerName} has created a professional email signature for you on the ${displayTeamName} team.`,
    '',
    'View and install your new signature using the secure link below:',
    '',
    actionUrl,
    '',
    `This invite link will expire in ${expiresIn}.`,
    '',
    "If you weren't expecting this signature invite, you can safely ignore this email.",
    '',
    '© 2026 Sig Signature. All rights reserved.',
  ].join('\n');

  return sendEmail({
    to,
    subject: `${displayOwnerName} shared your new email signature`,
    html,
    text,
  });
}

/**
 * Sends a security alert email when the user's password is changed.
 */
async function sendPasswordChangedEmail({ to, firstName, time, deviceInfo, ipAddress, resetUrl }) {
  const greetingName = firstName || 'there';
  const frontendBase = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
  const finalResetUrl = resetUrl || `${frontendBase}/forgot`;
  const rawHtml = getTemplate('securityPasswordChanged', 'security_password_changed.html');
  const html = renderTemplate(rawHtml, {
    firstName: greetingName,
    time: time || new Date().toUTCString(),
    deviceInfo: deviceInfo || 'Unknown device',
    ipAddress: ipAddress || 'Unknown IP',
    resetUrl: finalResetUrl,
  });

  const text = [
    `Hi ${greetingName},`,
    '',
    'Security Alert: Your Sig Signature password was recently changed.',
    '',
    `Time: ${time || new Date().toUTCString()}`,
    `Device: ${deviceInfo || 'Unknown device'}`,
    `IP Address: ${ipAddress || 'Unknown IP'}`,
    '',
    `If this was not you, reset your password now: ${finalResetUrl}`,
    '',
    '© 2026 Sig Signature. All rights reserved.',
  ].join('\n');

  return sendEmail({
    to,
    subject: 'Security Alert: Your Sig Signature password was changed',
    html,
    text,
  });
}

/**
 * Sends a security notification email when other sessions are revoked.
 */
async function sendSessionsRevokedEmail({ to, firstName, time, deviceInfo, ipAddress, resetUrl }) {
  const greetingName = firstName || 'there';
  const frontendBase = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
  const finalResetUrl = resetUrl || `${frontendBase}/forgot`;
  const rawHtml = getTemplate('securitySessionsRevoked', 'security_sessions_revoked.html');
  const html = renderTemplate(rawHtml, {
    firstName: greetingName,
    time: time || new Date().toUTCString(),
    deviceInfo: deviceInfo || 'Unknown device',
    ipAddress: ipAddress || 'Unknown IP',
    resetUrl: finalResetUrl,
  });

  const text = [
    `Hi ${greetingName},`,
    '',
    'Security Notification: All other active sessions for your Sig Signature account were recently revoked and signed out.',
    '',
    `Time: ${time || new Date().toUTCString()}`,
    `Device: ${deviceInfo || 'Unknown device'}`,
    `IP Address: ${ipAddress || 'Unknown IP'}`,
    '',
    `If this was not you, reset your password now: ${finalResetUrl}`,
    '',
    '© 2026 Sig Signature. All rights reserved.',
  ].join('\n');

  return sendEmail({
    to,
    subject: 'Security Notification: Other sessions were signed out',
    html,
    text,
  });
}

/**
 * Sends a final confirmation email after account deletion.
 */
async function sendAccountDeletedEmail({ to, firstName }) {
  const greetingName = firstName || 'there';
  const rawHtml = getTemplate('accountDeleted', 'account_deleted.html');
  const html = renderTemplate(rawHtml, {
    firstName: greetingName,
  });

  const text = [
    `Hi ${greetingName},`,
    '',
    'Your Sig Signature account has been permanently deleted as requested, along with all associated signatures and data.',
    '',
    'Thank you for using Sig Signature.',
    '',
    '© 2026 Sig Signature. All rights reserved.',
  ].join('\n');

  return sendEmail({
    to,
    subject: 'Your Sig Signature account was deleted',
    html,
    text,
  });
}

module.exports = {
  sendEmail,
  sendPasswordResetEmail,
  sendVerificationEmail,
  sendTeamInviteEmail,
  sendPasswordChangedEmail,
  sendSessionsRevokedEmail,
  sendAccountDeletedEmail,
  escapeHtml,
  renderTemplate,
};
