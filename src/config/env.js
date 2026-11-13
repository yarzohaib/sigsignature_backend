const { z } = require("zod");

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(8000),
  
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  
  JWT_ACCESS_SECRET: z.string().min(16, "JWT_ACCESS_SECRET must be at least 16 characters long"),
  JWT_REFRESH_SECRET: z.string().min(16, "JWT_REFRESH_SECRET must be at least 16 characters long"),
  JWT_ACCESS_EXPIRES_IN: z.string().default("15m"),
  JWT_REFRESH_EXPIRES_IN: z.string().default("7d"),
  JWT_ISSUER: z.string().default("sigsignature.com"),
  JWT_AUDIENCE: z.string().default("sigsignature-app"),

  SESSION_TTL_DAYS: z.coerce.number().default(7),
  
  FRONTEND_URL: z.string().default("http://localhost:3000"),
  BACKEND_URL: z.string().optional(),
  APP_URL: z.string().optional(),
  TRUST_PROXY_HOPS: z.coerce.number().default(1),
  TURNSTILE_SECRET_KEY: z.string().optional(),

  // Gmail integration (optional: the feature stays switched off until these are set)
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  INTEGRATION_ENCRYPTION_KEY: z.string().optional(),
  
  AWS_REGION: z.string().default("ap-southeast-2"),
  S3_BUCKET: z.string().optional(),
  S3_PUBLIC_BASE_URL: z.string().optional(),
  MAIL_ENABLED: z.string().default("false"),
  MAIL_FROM: z.string().optional(),
  SIGNATURE_LIMIT_PER_USER: z.coerce.number().default(3),
  TEAM_MEMBER_LIMIT_FREE: z.coerce.number().default(3),
  TEAM_INVITE_TTL_DAYS: z.coerce.number().default(14),
  TEAM_SEND_DAILY_LIMIT: z.coerce.number().default(10),
  TEAM_SEND_MAX_PER_MEMBER: z.coerce.number().default(5),
  TEAM_SEND_COOLDOWN_SECONDS: z.coerce.number().default(60),
});

function validateEnv() {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    console.error("❌ Environment validation failed on startup:");
    result.error.issues.forEach((issue) => {
      console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
    });
    process.exit(1);
  }

  return result.data;
}

const env = validateEnv();

module.exports = env;
