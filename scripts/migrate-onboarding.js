const db = require('../src/config/prisma');

async function migrate() {
  try {
    const q = db.raw.sql`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "onboardingSeenAt" TIMESTAMP WITH TIME ZONE`.affectedCount().build();
    await db.runtime().execute(q);
    const q2 = db.raw.sql`ALTER TABLE "User" ALTER COLUMN "onboardingSeenAt" TYPE TIMESTAMP WITH TIME ZONE`.affectedCount().build();
    await db.runtime().execute(q2);
    console.log('✅ Migration successful: "onboardingSeenAt" column added/updated to TIMESTAMP WITH TIME ZONE on "User".');
  } catch (err) {
    console.error('❌ Migration failed:', err.message);
    process.exit(1);
  } finally {
    process.exit(0);
  }
}

migrate();
