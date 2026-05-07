/**
 * FinOwl — Create GBP Stripe Payment Links
 * ─────────────────────────────────────────
 * Run this ONCE after adding STRIPE_SECRET_KEY to your environment.
 *
 *   STRIPE_SECRET_KEY=sk_live_xxx node scripts/create-gbp-stripe-links.js
 *
 * The script creates GBP products, prices, and payment links for all 8 plans
 * that were previously in USD. When done, it prints the new buy.stripe.com URLs
 * to paste into public/index.html (replacing the STRIPE_LINKS object).
 *
 * After pasting the new links, deploy with: npm run deploy (or push via Render).
 *
 * NOTES:
 *  - dormant-monthly is already GBP (£15/mo) — this script skips it.
 *  - Trial periods: set TRIAL_DAYS_DORMANT and TRIAL_DAYS_LTD below if needed.
 *  - Biennial plans use Stripe interval: 'year', interval_count: 2.
 *  - All amounts are in pence (GBP minor unit) per Stripe convention.
 */

'use strict';

const Stripe = require('stripe');

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) {
    console.error('ERROR: STRIPE_SECRET_KEY is not set.');
    console.error('Run: STRIPE_SECRET_KEY=sk_live_xxx node scripts/create-gbp-stripe-links.js');
    process.exit(1);
}

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

// ── Trial period configuration ────────────────────────────────────────────────
// Set to 0 to disable trials. Adjust per Stripe dashboard audit findings.
const TRIAL_DAYS_DORMANT = 0;  // e.g. 14 for a 14-day free trial
const TRIAL_DAYS_LTD     = 0;  // e.g. 14 for a 14-day free trial

// ── Success URL ───────────────────────────────────────────────────────────────
const SUCCESS_URL = 'https://finowl.co.uk/checkout-success.html?session_id={CHECKOUT_SESSION_ID}';

// ── Plan definitions (amounts in pence) ──────────────────────────────────────
// Existing dormant-monthly (£15/mo) is ALREADY GBP — do NOT recreate it.
const PLANS = [
    // Sole Trader
    {
        key:            'monthly',
        productName:    'FinOwl — Sole Trader',
        description:    'Autonomous bookkeeping for UK sole traders · MTD ready',
        amountPence:    5900,          // £59.00
        interval:       'month',
        intervalCount:  1,
        trialDays:      0,
    },
    {
        key:            'annual',
        productName:    'FinOwl — Sole Trader',
        description:    'Autonomous bookkeeping for UK sole traders · MTD ready · Annual',
        amountPence:    64900,         // £649.00 (1 month free vs monthly)
        interval:       'year',
        intervalCount:  1,
        trialDays:      0,
    },
    {
        key:            'biennial',
        productName:    'FinOwl — Sole Trader',
        description:    'Autonomous bookkeeping for UK sole traders · MTD ready · 2-Year',
        amountPence:    129800,        // £1,298.00 (2 months free vs monthly)
        interval:       'year',
        intervalCount:  2,
        trialDays:      0,
    },

    // Dormant Business (monthly is already GBP — annual and biennial only)
    {
        key:            'dormant-annual',
        productName:    'FinOwl — Dormant Business',
        description:    'Compliance-only bookkeeping for dormant UK companies · Annual',
        amountPence:    16500,         // £165.00 (1 month free vs monthly)
        interval:       'year',
        intervalCount:  1,
        trialDays:      TRIAL_DAYS_DORMANT,
    },
    {
        key:            'dormant-biennial',
        productName:    'FinOwl — Dormant Business',
        description:    'Compliance-only bookkeeping for dormant UK companies · 2-Year',
        amountPence:    33000,         // £330.00 (2 months free vs monthly)
        interval:       'year',
        intervalCount:  2,
        trialDays:      TRIAL_DAYS_DORMANT,
    },

    // Limited Company
    {
        key:            'ltd-monthly',
        productName:    'FinOwl — Limited Company',
        description:    'Autonomous bookkeeping for UK limited companies · MTD ready',
        amountPence:    8900,          // £89.00
        interval:       'month',
        intervalCount:  1,
        trialDays:      TRIAL_DAYS_LTD,
    },
    {
        key:            'ltd-annual',
        productName:    'FinOwl — Limited Company',
        description:    'Autonomous bookkeeping for UK limited companies · MTD ready · Annual',
        amountPence:    97900,         // £979.00 (1 month free vs monthly)
        interval:       'year',
        intervalCount:  1,
        trialDays:      TRIAL_DAYS_LTD,
    },
    {
        key:            'ltd-biennial',
        productName:    'FinOwl — Limited Company',
        description:    'Autonomous bookkeeping for UK limited companies · MTD ready · 2-Year',
        amountPence:    195800,        // £1,958.00 (2 months free vs monthly)
        interval:       'year',
        intervalCount:  2,
        trialDays:      TRIAL_DAYS_LTD,
    },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

async function findOrCreateProduct(name, description) {
    // Search for existing product by name to avoid duplicates
    const products = await stripe.products.search({
        query: `name:"${name}" AND active:"true"`,
    });
    if (products.data.length > 0) {
        console.log(`  ↳ Reusing existing product: ${products.data[0].id}`);
        return products.data[0];
    }
    const product = await stripe.products.create({ name, description, active: true });
    console.log(`  ↳ Created product: ${product.id}`);
    return product;
}

async function createPrice(productId, plan) {
    const priceData = {
        product:     productId,
        currency:    'gbp',
        unit_amount: plan.amountPence,
        recurring: {
            interval:       plan.interval,
            interval_count: plan.intervalCount,
        },
        metadata: {
            finowl_plan: plan.key,
            created_by:  'create-gbp-stripe-links.js',
        },
    };

    if (plan.trialDays > 0) {
        priceData.recurring.trial_period_days = plan.trialDays;
    }

    const price = await stripe.prices.create(priceData);
    console.log(`  ↳ Created GBP price: ${price.id} (£${(plan.amountPence / 100).toFixed(2)})`);
    return price;
}

async function createPaymentLink(priceId, successUrl) {
    const link = await stripe.paymentLinks.create({
        line_items: [{ price: priceId, quantity: 1 }],
        after_completion: {
            type:     'redirect',
            redirect: { url: successUrl },
        },
    });
    return link;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    console.log('FinOwl — Creating GBP Stripe Payment Links');
    console.log('══════════════════════════════════════════\n');

    // Verify we're using the right key type
    const mode = STRIPE_SECRET_KEY.startsWith('sk_live') ? 'LIVE' : 'TEST';
    console.log(`Stripe mode: ${mode}\n`);
    if (mode === 'TEST') {
        console.log('⚠️  Using TEST key — links will not charge real customers.');
        console.log('   Run with a LIVE key for production links.\n');
    }

    const results = {};

    for (const plan of PLANS) {
        console.log(`\n[${plan.key}] £${(plan.amountPence / 100).toFixed(2)} / ${plan.intervalCount > 1 ? plan.intervalCount + ' ' : ''}${plan.interval}`);

        try {
            const product = await findOrCreateProduct(plan.productName, plan.description);
            const price   = await createPrice(product.id, plan);
            const link    = await createPaymentLink(price.id, SUCCESS_URL);

            results[plan.key] = link.url;
            console.log(`  ↳ Payment link: ${link.url}`);
        } catch (err) {
            console.error(`  ✗ Failed: ${err.message}`);
            results[plan.key] = `ERROR: ${err.message}`;
        }
    }

    console.log('\n\n══════════════════════════════════════════');
    console.log('DONE — Paste these into public/index.html (STRIPE_LINKS object)');
    console.log('══════════════════════════════════════════\n');

    console.log('var STRIPE_LINKS = {');
    console.log("    // Sole Trader");
    console.log(`    'monthly':           '${results['monthly'] || 'ERROR'}',`);
    console.log(`    'annual':            '${results['annual'] || 'ERROR'}',`);
    console.log(`    'biennial':          '${results['biennial'] || 'ERROR'}',`);
    console.log("    // Dormant Business");
    console.log("    'dormant-monthly':   'https://buy.stripe.com/6oUbJ18Ld4GIcT00hj2Ji01',  // already GBP — unchanged");
    console.log(`    'dormant-annual':    '${results['dormant-annual'] || 'ERROR'}',`);
    console.log(`    'dormant-biennial':  '${results['dormant-biennial'] || 'ERROR'}',`);
    console.log("    // Limited Company");
    console.log(`    'ltd-monthly':       '${results['ltd-monthly'] || 'ERROR'}',`);
    console.log(`    'ltd-annual':        '${results['ltd-annual'] || 'ERROR'}',`);
    console.log(`    'ltd-biennial':      '${results['ltd-biennial'] || 'ERROR'}'`);
    console.log('};');

    console.log('\n\nNext steps:');
    console.log('  1. Replace STRIPE_LINKS in public/index.html with the block above');
    console.log('  2. Run: git add public/index.html && git commit -m "fix: Stripe checkout links now GBP"');
    console.log('  3. Push to production via Render');
    console.log('  4. Verify one test checkout shows £ symbol on Stripe checkout page');
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
