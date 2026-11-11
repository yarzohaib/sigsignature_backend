const { Pool } = require("pg");
require("dotenv").config();

async function runReferralMigration() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("❌ DATABASE_URL is not set in environment or .env file.");
    process.exit(1);
  }

  const pool = new Pool({ connectionString });

  try {
    console.log("⏳ Starting referral system migration on User table...");

    // 1. Add referralCode column
    await pool.query(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "referralCode" TEXT;`);
    console.log('✅ Column "referralCode" ensured.');

    // 2. Add referredById column
    await pool.query(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "referredById" TEXT;`);
    console.log('✅ Column "referredById" ensured.');

    // 3. Add proTrialUntil timestamp column
    await pool.query(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "proTrialUntil" TIMESTAMP WITH TIME ZONE;`);
    console.log('✅ Column "proTrialUntil" ensured.');

    // 4. Add referralCount integer column with default 0
    await pool.query(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "referralCount" INTEGER DEFAULT 0;`);
    console.log('✅ Column "referralCount" ensured.');

    // 5. Create unique index on referralCode
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS "User_referralCode_key" ON "User"("referralCode");`);
    console.log('✅ Unique index "User_referralCode_key" ensured.');

    console.log("\n🎉 All referral migrations completed successfully!");
  } catch (err) {
    console.error("❌ Migration failed:", err.message);
    process.exit(1);
  } finally {
    await pool.end();
    process.exit(0);
  }
}

runReferralMigration();
