const router = require('express').Router();
const path = require('path');
const { body } = require('express-validator');
const db = require('../config/db');
const { validate } = require('../middleware/errorHandler');
const { requireAuth } = require('../middleware/auth');
const { paymentProofUpload } = require('../middleware/paymentUpload');
const { uploadPaymentProof } = require('../services/paymentProofStorageService');

router.use(requireAuth);

router.get('/plans', async (req, res, next) => {
  try {
    const { rows } = await db.query('SELECT * FROM subscription_plans ORDER BY price_php ASC');
    res.json({ plans: rows });
  } catch (err) { next(err); }
});

router.get('/me', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT s.*, p.code, p.name, p.price_php, p.scan_limit, p.max_members
       FROM subscriptions s JOIN subscription_plans p ON p.id = s.plan_id
       WHERE s.user_id = $1 AND s.status = 'active'`,
      [req.user.id]
    );
    res.json(rows[0] || null);
  } catch (err) { next(err); }
});

// In production this endpoint would create a checkout session with the payment
// provider (e.g. PayMongo/GCash/Stripe) and only flip the subscription active
// once a webhook confirms payment. Wired here as a clean seam for that integration.
router.post(
  '/checkout',
  [body('planCode').isIn(['plus', 'family'])],
  validate,
  async (req, res, next) => {
    try {
      const { planCode } = req.body;
      const plan = await db.query('SELECT * FROM subscription_plans WHERE code = $1', [planCode]);
      if (!plan.rows[0]) return res.status(404).json({ error: 'Plan not found' });

      // Placeholder response: real integration returns a redirect_url from the PSP.
      res.json({
        checkoutSessionId: `mock_${Date.now()}`,
        redirectUrl: null,
        message: 'Payment provider integration required (PayMongo/GCash/Stripe) to complete checkout.',
        plan: plan.rows[0],
      });
    } catch (err) { next(err); }
  }
);

router.post('/cancel', async (req, res, next) => {
  try {
    await db.query(
      `UPDATE subscriptions SET cancel_at_period_end = TRUE WHERE user_id = $1 AND status = 'active'`,
      [req.user.id]
    );
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ------------------------------------------------------------------
// GCash InstaPay manual payment flow.
// The customer scans our merchant QR, pays in the GCash app, then submits
// a reference number and/or screenshot here. An admin reviews it in
// /api/admin/payments and approving it activates the subscription.
// ------------------------------------------------------------------

// Static merchant QR code - same image for every user/plan.
router.get('/payment-qr', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'payment-assets', 'gcash-instapay-qr.jpeg'));
});

router.post(
  '/payments/gcash',
  paymentProofUpload.single('proof'),
  [
    body('planCode').isIn(['plus', 'family']),
    body('referenceNumber').optional().trim().isLength({ max: 100 }),
  ],
  validate,
  async (req, res, next) => {
    try {
      const { planCode, referenceNumber } = req.body;
      const plan = await db.query('SELECT * FROM subscription_plans WHERE code = $1', [planCode]);
      if (!plan.rows[0]) return res.status(404).json({ error: 'Plan not found' });

      if (!referenceNumber && !req.file) {
        return res.status(422).json({
          error: 'Provide a GCash reference number, a screenshot, or both, so this can be verified.',
        });
      }

      const proofPath = req.file
        ? await uploadPaymentProof({
            userId: req.user.id,
            buffer: req.file.buffer,
            mimetype: req.file.mimetype,
            originalname: req.file.originalname,
          })
        : null;

      const { rows } = await db.query(
        `INSERT INTO manual_payments (user_id, plan_id, amount_php, reference_number, proof_image_path)
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [req.user.id, plan.rows[0].id, plan.rows[0].price_php, referenceNumber || null, proofPath]
      );

      res.status(201).json({
        payment: rows[0],
        message: 'Payment submitted. An admin will review and activate your plan shortly.',
      });
    } catch (err) { next(err); }
  }
);

// The customer's own submissions, most recent first - lets the app show
// "pending review" / "approved" / "rejected" state.
router.get('/payments/mine', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT mp.*, p.code AS plan_code, p.name AS plan_name
       FROM manual_payments mp JOIN subscription_plans p ON p.id = mp.plan_id
       WHERE mp.user_id = $1 ORDER BY mp.created_at DESC LIMIT 20`,
      [req.user.id]
    );
    res.json({ items: rows });
  } catch (err) { next(err); }
});

module.exports = router;
