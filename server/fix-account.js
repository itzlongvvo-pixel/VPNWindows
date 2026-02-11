const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    try {
        await prisma.subscriptionCode.update({
            where: { code: 'NERA-45B3-ETF7' },
            data: {
                status: 'ACTIVE',
                isValid: true,
                expiresAt: expiresAt
            }
        });
        console.log('✅ Updated NERA-45B3-ETF7');
        console.log('   Expires:', expiresAt.toISOString());

        const record = await prisma.subscriptionCode.findUnique({
            where: { code: 'NERA-45B3-ETF7' }
        });
        console.log('   Record:', record);
    } catch (err) {
        console.error('❌ Error:', err.message);
    } finally {
        await prisma.$disconnect();
    }
}

main();
