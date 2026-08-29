/**
 * One-off helper: promote an existing user to the 'admin' role so they can
 * log into /admin/payments.html and the /api/admin/* endpoints.
 *
 * There is no API route for this on purpose - granting admin access should
 * never be reachable by a regular authenticated request. Run this directly
 * against the database instead.
 *
 * Usage:
 *   node scripts/make-admin.js someone@example.com
 *
 * The account must already exist (register it first via POST /api/auth/register
 * or through the app's sign-up screen) - this script only changes its role.
 */
require('dotenv').config();
const db = require('../config/db');

async function main() {
  const email = process.argv[2];
  if (!email) {
    console.error('Usage: node scripts/make-admin.js <email>');
    process.exit(1);
  }

  const { rows } = await db.query(
    `UPDATE users SET role = 'admin', updated_at = now()
     WHERE email = $1 RETURNING id, email, role`,
    [email.toLowerCase()]
  );

  if (!rows[0]) {
    console.error(`No user found with email "${email}". Register the account first.`);
    process.exit(1);
  }

  console.log(`✓ ${rows[0].email} is now role="${rows[0].role}" (id: ${rows[0].id})`);
  process.exit(0);
}

main().catch((err) => {
  console.error('Failed to promote user:', err.message);
  process.exit(1);
});
