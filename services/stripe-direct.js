/**
 * Stripe Direct service for FinOwl.
 * Uses the user's own Stripe account directly — no Connect dependency.
 * Last updated: 2026-05-05 — valid sk_test_51TTWFi... key deployed; STRIPE_CONNECT_ACCOUNT_ID removed.
 *
 * Environment variables required:
 * - STRIPE_SECRET_KEY: User's own Stripe secret key (sk_live_... or sk_test_...)
 * - STRIPE_WEBHOOK_SECRET: Webhook signing secret from Stripe dashboard (whsec_...)
 * - APP_URL: Application base URL (defaults to https://finowl.co.uk)
 */

let stripeClient = null;

/**
 * Lazily initialise the Stripe client using the user's own secret key.
 * No stripeAccount scoping — this is a direct account integration.
 */
function getStripe() {
  if (!stripeClient) {
    const Stripe = require('stripe');
    const secretKey = process.env.STRIPE_SECRET_KEY;
    if (!secretKey) {
      throw new Error('STRIPE_SECRET_KEY is not configured.');
    }
    stripeClient = new Stripe(secretKey, {
      apiVersion: '2024-04-10',
    });
  }
  return stripeClient;
}

/**
 * Plan definitions — all prices in pence (GBP).
 *
 * Pricing:
 *   Sole Trader:  £59/mo  |  £649/yr  |  £1,298/2yr
 *   Dormant:      £15/mo  |  £165/yr  |  £330/2yr
 *   Limited:      £89/mo  |  £979/yr  |  £1,958/2yr
 */
const PLANS = {
  // ── Sole Trader ──────────────────────────
  monthly: {
    name: 'FinOwl — Sole Trader Monthly',
    amount: 5900,
    interval: 'month',
    interval_count: 1,
    trial_days: 30,
  },
  annual: {
    name: 'FinOwl — Sole Trader Annual',
    amount: 64900,
    interval: 'year',
    interval_count: 1,
    trial_days: 30,
  },
  biennial: {
    name: 'FinOwl — Sole Trader 2-Year',
    amount: 129800,
    interval: 'year',
    interval_count: 2,
    trial_days: 30,
  },

  // ── Dormant Business ─────────────────────
  'dormant-monthly': {
    name: 'FinOwl — Dormant Business Monthly',
    amount: 1500,
    interval: 'month',
    interval_count: 1,
    trial_days: 30,
  },
  'dormant-annual': {
    name: 'FinOwl — Dormant Business Annual',
    amount: 16500,
    interval: 'year',
    interval_count: 1,
    trial_days: 30,
  },
  'dormant-biennial': {
    name: 'FinOwl — Dormant Business 2-Year',
    amount: 33000,
    interval: 'year',
    interval_count: 2,
    trial_days: 30,
  },

  // ── Limited Company ──────────────────────
  'ltd-monthly': {
    name: 'FinOwl — Limited Company Monthly',
    amount: 8900,
    interval: 'month',
    interval_count: 1,
    trial_days: 30,
  },
  'ltd-annual': {
    name: 'FinOwl — Limited Company Annual',
    amount: 97900,
    interval: 'year',
    interval_count: 1,
    trial_days: 30,
  },
  'ltd-biennial': {
    name: 'FinOwl — Limited Company 2-Year',
    amount: 195800,
    interval: 'year',
    interval_count: 2,
    trial_days: 30,
  },
};

/**
 * Ensure a Product + Price exists on the Stripe account.
 * Creates them if they don't exist yet.
 * Returns the Price ID.
 */
async function getOrCreatePrice(planKey) {
  const plan = PLANS[planKey];
  if (!plan) throw new Error(`Unknown plan: ${planKey}`);

  const stripe = getStripe();

  // List existing active prices to avoid duplicates
  const existing = await stripe.prices.list({ active: true, limit: 100 });
  const match = existing.data.find(
    (p) =>
      p.recurring?.interval === plan.interval &&
      p.recurring?.interval_count === plan.interval_count &&
      p.unit_amount === plan.amount &&
      p.currency === 'gbp'
  );

  if (match) return match.id;

  // Create product first
  const product = await stripe.products.create({
    name: plan.name,
    metadata: { planKey, created_by: 'stripe-direct-service' },
  });

  // Create price on the product
  const price = await stripe.prices.create({
    product: product.id,
    unit_amount: plan.amount,
    currency: 'gbp',
    recurring: {
      interval: plan.interval,
      interval_count: plan.interval_count,
    },
    nickname: planKey,
    metadata: { planKey },
  });

  console.log(`[stripe-direct] Created price ${price.id} for plan ${planKey}`);
  return price.id;
}

/**
 * Create a Stripe Checkout Session for the given plan.
 * Direct account — no Connect headers.
 *
 * @param {string} planKey - e.g. 'monthly', 'annual', 'ltd-monthly'
 * @param {string|null} customerEmail
 * @param {string|null} authToken - JWT for authenticated users (passed through to success URL)
 * @returns {Promise<string>} checkout session URL
 */
async function createCheckoutSession(planKey, customerEmail, authToken) {
  const plan = PLANS[planKey];
  if (!plan) throw new Error(`Invalid plan: ${planKey}`);

  const stripe = getStripe();
  const appUrl = process.env.APP_URL || 'https://finowl.co.uk';

  const priceId = await getOrCreatePrice(planKey);

  const sessionParams = {
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    subscription_data: {
      trial_period_days: plan.trial_days,
      metadata: { plan: planKey },
    },
    success_url: `${appUrl}/checkout/success?session_id={CHECKOUT_SESSION_ID}&plan=${planKey}&token=${authToken || ''}`,
    cancel_url: `${appUrl}/#pricing`,
    allow_promotion_codes: true,
    billing_address_collection: 'required',
  };

  if (customerEmail) {
    sessionParams.customer_email = customerEmail;
  }

  const session = await stripe.checkout.sessions.create(sessionParams);
  console.log(`[stripe-direct] Created checkout session ${session.id} for plan ${planKey}`);
  return session.url;
}

/**
 * Verify a Stripe Checkout Session.
 * Used by the success page to confirm payment before activating subscription.
 *
 * @param {string} sessionId
 * @returns {Promise<object>} session details
 */
async function verifyCheckoutSession(sessionId) {
  const stripe = getStripe();

  const session = await stripe.checkout.sessions.retrieve(sessionId, {
    expand: ['subscription'],
  });

  if (session.payment_status !== 'paid' && session.status !== 'complete') {
    // Allow 'trialing' — trial subscriptions report payment_status = 'no_payment_needed'
    const sub = session.subscription;
    const subStatus = sub?.status;
    if (!['active', 'trialing'].includes(subStatus)) {
      throw Object.assign(new Error('Payment not completed'), {
        status: session.payment_status,
      });
    }
  }

  const subscription = session.subscription;
  const planKey =
    (subscription && subscription.metadata && subscription.metadata.plan)
    || session.metadata?.plan
    || null;

  return {
    subscription_id: typeof subscription === 'object' ? subscription.id : subscription,
    customer_id: session.customer,
    customer_email: session.customer_email,
    amount_total: session.amount_total,
    currency: session.currency,
    planKey,
    subscription_status: subscription?.status || 'active',
  };
}

module.exports = { createCheckoutSession, verifyCheckoutSession, PLANS, getStripe };
