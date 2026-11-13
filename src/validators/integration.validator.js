const { z } = require("zod");

const connectGmailSchema = z
  .object({
    frontendOrigin: z.string().url().max(200).optional(),
  })
  .strict();

const pushGmailSchema = z
  .object({
    signatureId: z.string().uuid("Invalid signature id"),
    // The exported signature HTML. It is cleaned and size checked again on the server.
    html: z.string().min(20, "Signature HTML is too short").max(60000, "Signature HTML is too large"),
  })
  .strict();

module.exports = { connectGmailSchema, pushGmailSchema };
