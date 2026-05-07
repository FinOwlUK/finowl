/**
 * Stripe Connect service for FinOwl.
 * Uses the owner's Stripe connected account via Polsia Stripe Connect.
 *
 * Environment variables required:
 * - STRIPE_SECRET_KEY: Platform or connected account secret key (sk_live_...)
 * - STRIPE_CONNECT_ACCOUNT_ID: Connected account ID (acct_...)
 * - STRIPE_WEBHOOK_SECRET: Webhook signing secret (whsec_...)
 */

let stripeClient = null;
let cachedPriceIds = null;

/**
 * Lazily initialise the Stripe client scoped to the connected account.
 * Uses Stripe-Account header so all requests target the connected account.
 */
function getStripe() {
  if (!stripeClient) {
    const Stripe = require('stripe');
    const secretKey = process.env.STRIPE_SECRET_KEY;
    if (!secretKey) {
      throw new Error('STRIPE_SECRET_KEY is not configured. Please contact support.');
    }
    stripeClient = new Stripe(secretKey, {
      // Stripe-Account header scopes all API calls to the connected account
      stripeAccount: process.env.STRIPE_CONNECT_ACCOUNT_ID,
      apiVersion: '2024-04-10',
    });
  }
  return stripeClient;
}

/**
 * Plan definitions — all with 30-day trial.
 * Amounts are in pence (GBP).
 *
 * Pricing (landing page):
 *   Sole Trader:  £79/mo  |  £649/yr (1 mo free)  |  £1,298/2yr (2 mo free)
 *   Dormant:      £15/mo  |  £165/yr (1 mo free)   |  £330/2yr (2 mo free)
 *   Limited:      £89/mo  |  £979/yr (1 mo free)   |  £1,958/2yr (2 mo free)
 */
const PLANS = {
  // ── Sole Trader ─────────────────────────
  monthly: {
    name: 'FinOwl — Sole Trader Monthly',
    amount: 5900,    // £59.00
    interval: 'month',
    interval_count: 1,
    trial_days: 30,
  },
  annual: {
    name: 'FinOwl — Sole Trader Annual',
    amount: 64900,   // £649.00
    interval: 'year',
    interval_count: 1,
    trial_days: 30,
  },
  biennial: {
    name: 'FinOwl — Sole Trader 2-Year',
    amount: 129800,  // £1,298.00
    interval: 'year',
    interval_count: 2,
    trial_days: 30,
  },

  // ── Dormant Business ────────────────────
  'dormant-monthly': {
    name: 'FinOwl — Dormant Business Monthly',
    amount: 1500,    // £15.00
    interval: 'month',
    interval_count: 1,
    trial_days: 30,
  },
  'dormant-annual': {
    name: 'FinOwl — Dormant Business Annual',
    amount: 16500,   // £165.00
    interval: 'year',
    interval_count: 1,
    trial_days: 30,
  },
  'dormant-biennial': {
    name: 'FinOwl — Dormant Business 2-Year',
    amount: 33000,   // £330.00
    interval: 'year',
    interval_count: 2,
    trial_days: 30,
  },

  // ── Limited Company ─────────────────────
  'ltd-monthly': {
    name: 'FinOwl — Limited Company Monthly',
    amount: 8900,    // £89.00
    interval: 'month',
    interval_count: 1,
    trial_days: 30,
  },
  'ltd-annual': {
    name: 'FinOwl — Limited Company Annual',
    amount: 97900,   // £979.00
    interval: 'year',
    interval_count: 1,
    trial_days: 30,
  },
  'ltd-biennial': {
    name: 'FinOwl — Limited Company 2-Year',
    amount: 195800,  // £1,958.00
    interval: 'year',
    interval_count: 2,
    trial_days: 30,
  },
};

/**
 * Ensure a Product + Price exists on the connected Stripe account.
 * Creates them if they don't exist yet.
 * Returns the Price ID.
 */
async function getOrCreatePrice(planKey) {
  const plan = PLANS[planKey];
  if (!plan) throw new Error(`Unknown plan: ${planKey}`);

  const stripe = getStripe();
  const productPrefix = `finowl-${planKey}`;

  // List existing prices on the connected account
  const existing = await stripe.prices.list(
    { active: true, limit: 100 },
    { stripeAccount: process.env.STRIPE_CONNECT_ACCOUNT_ID }
  );
  const match = existing.data.find(
    (p) =>
      p.recurring?.interval === plan.interval &&
      p.recurring?.interval_count === plan.interval_count &&
      p.unit_amount === plan.amount &&
      p.currency === 'gbp'
  );

  if (match) return match.id;

  // Product doesn't exist — create it first
  const product = await stripe.products.create(
    {
      name: plan.name,
      metadata: { planKey, created_by: 'stripe-connect-service' },
    },
    { stripeAccount: process.env.STRIPE_CONNECT_ACCOUNT_ID }
  );

  // Create the Price on the connected account
  const price = await stripe.prices.create(
    {
      product: product.id,
      unit_amount: plan.amount,
      currency: 'gbp',
      recurring: {
        interval: plan.interval,
        interval_count: plan.interval_count,
      },
      nickname: planKey,
      metadata: { planKey },
    },
    { stripeAccount: process.env.STRIPE_CONNECT_ACCOUNT_ID }
  );

  console.log(`[stripe-connect] Created price ${price.id} for plan ${planKey}`);
  return price.id;
}

/**
 * Create a Stripe Checkout Session for the given plan.
 * Uses Stripe Connect: on_behalf_of targets the connected account,
 * and transfer_data routes the charge to the connected account.
 *
 * @param {string} planKey  - 'monthly' | 'annual' | 'biennial'
 * @param {string|null} customerEmail
 * @param {string|null} authToken - JWT for authenticated users
 * @returns {Promise<string>} checkout session URL
 */
async function createCheckoutSession(planKey, customerEmail, authToken) {
  const plan = PLANS[planKey];
  if (!plan) throw new Error(`Invalid plan: ${planKey}`);

  const stripe = getStripe();
  const connectedAccountId = process.env.STRIPE_CONNECT_ACCOUNT_ID;
  const appUrl = process.env.APP_URL || 'https://finowl.co.uk';

  // Get or create the Price on the connected account
  const priceId = await getOrCreatePrice(planKey);

  const sessionParams = {
    // Stripe Connect: charge the connected account
    on_behalf_of: connectedAccountId,
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    subscription_data: {
      // trial_period_days must be <= 730 for Stripe Connect
      trial_period_days: plan.trial_days,
      // Use 'plan' key so server.js verify and checkout-success.html can read it back
      metadata: { plan: planKey },
      // Stripe Connect: transfer the charge to the connected account
      transfer_data: { destination: connectedAccountId },
    },
    success_url: `${appUrl}/checkout/success?session_id={CHECKOUT_SESSION_ID}&plan=${planKey}&token=${authToken || ''}`,
    cancel_url: `${appUrl}/#pricing`,
    allow_promotion_codes: true,
    billing_address_collection: 'required',
  };

  if (customerEmail) {
    sessionParams.customer_email = customerEmail;
  }

  // Create the session scoped to the connected account
  const session = await stripe.checkout.sessions.create(sessionParams, {
    stripeAccount: connectedAccountId,
  });

  console.log(`[stripe-connect] Created checkout session ${session.id} for plan ${planKey}`);
  return session.url;
}

/**
 * Verify a Stripe Checkout Session and return its details.
 * Used by the success page to confirm payment before activating the subscription.
 *
 * @param {string} sessionId
 * @returns {Promise<object>} session details
 */
async function verifyCheckoutSession(sessionId) {
  const stripe = getStripe();
  const connectedAccountId = process.env.STRIPE_CONNECT_ACCOUNT_ID;

  const session = await stripe.checkout.sessions.retrieve(sessionId, {
    stripeAccount: connectedAccountId,
    // Expand to include subscription object so we can read its metadata
    expand: ['subscription'],
  });

  if (session.payment_status !== 'paid') {
    throw Object.assign(new Error('Payment not completed'), {
      status: session.payment_status,
    });
  }

  // Metadata set in subscription_data is stored on the subscription object
  const subscription = session.subscription;
  const planKey =
    (subscription && subscription.metadata && subscription.metadata.plan)
    || session.metadata?.plan
    || null;

  return {
    subscription_id: session.subscription,
    customer_id: session.customer,
    customer_email: session.customer_email,
    amount_total: session.amount_total / 100,
    currency: session.currency,
    planKey: planKey,
  };
}

module.exports = { createCheckoutSession, verifyCheckoutSession, PLANS };