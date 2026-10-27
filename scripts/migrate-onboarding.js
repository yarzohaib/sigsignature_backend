const db = require('../src/config/prisma');

async function migrate() {
  try {
    const q = db.raw.sql`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "onboardingSeenAt" TIMESTAMP(3)`.affectedCount().build();
    await db.runtime().execute(q);
    console.log('✅ Migration successful: "onboardingSeenAt" column added to "User" (or already exists).');
  } catch (err) {
    console.error('❌ Migration failed:', err.message);
    process.exit(1);
  } finally {
    process.exit(0);
  }
}

migrate();
