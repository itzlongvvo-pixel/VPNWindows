/**
 * Nera VPN™ - Database Seed Script
 * 
 * Creates test subscription codes for development.
 * Run with: npm run db:seed
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const TEST_CODES = [
    { code: 'NERA-1234-5678', isValid: true },
    { code: 'NERA-AAAA-BBBB', isValid: true },
    { code: 'NERA-TEST-CODE', isValid: true },
    { code: 'DEMO-1111-2222', isValid: true },
    { code: 'DEMO-3333-4444', isValid: true },
    // Add an expired code for testing
    { code: 'NERA-EXPI-RED1', isValid: true, expiresAt: new Date('2020-01-01') },
    // Add an already-used code for testing  
    { code: 'NERA-USED-CODE', isValid: false, usedAt: new Date() },
];

async function main() {
    console.log('🌱 Seeding database with test subscription codes...\n');

    for (const code of TEST_CODES) {
        try {
            const result = await prisma.subscriptionCode.upsert({
                where: { code: code.code },
                update: {},
                create: code,
            });
            console.log(`  ✅ ${code.code} - ${code.isValid ? 'Valid' : 'Invalid'}`);
        } catch (error) {
            console.log(`  ⚠️ ${code.code} - Already exists or error`);
        }
    }

    console.log('\n🎉 Database seeded successfully!');
    console.log('\nYou can use these codes to test the auth flow:');
    console.log('  - NERA-1234-5678');
    console.log('  - DEMO-1111-2222');
    console.log('  - NERA-TEST-CODE');
}

main()
    .catch(console.error)
    .finally(async () => {
        await prisma.$disconnect();
    });
