const router = require('express').Router();
const { body } = require('express-validator');
const ctrl = require('../controllers/adminController');
const { validate } = require('../middleware/errorHandler');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// One-time, secret-gated self-promotion - must come before the requireAdmin
// gate below, since the caller isn't an admin yet when they use it.
router.post('/bootstrap', requireAuth, ctrl.bootstrapSelf);

router.use(requireAuth, requireAdmin);

router.get('/analytics/overview', ctrl.analyticsOverview);
router.get('/analytics/scans', ctrl.scanStats);
router.get('/analytics/subscriptions', ctrl.subscriptionStats);

router.get('/users', ctrl.listUsers);
router.patch('/users/:id', [body('isActive').optional().isBoolean(), body('role').optional().isIn(['user', 'admin', 'support'])], validate, ctrl.updateUserStatus);

router.get('/threat-domains', ctrl.listThreatDomains);
router.post(
  '/threat-domains',
  [body('domain').trim().notEmpty(), body('category').optional().isIn(['phishing', 'malware', 'scam', 'spam'])],
  validate,
  ctrl.addThreatDomain
);
router.delete('/threat-domains/:id', ctrl.removeThreatDomain);

router.get('/reports', ctrl.listReports);
router.patch(
  '/reports/:id',
  [body('status').isIn(['reviewing', 'confirmed', 'rejected'])],
  validate,
  ctrl.reviewReport
);

router.get('/payments', ctrl.listManualPayments);
router.get('/payments/:id/proof', ctrl.getPaymentProof);
router.patch(
  '/payments/:id',
  [body('status').isIn(['approved', 'rejected']), body('adminNotes').optional().trim().isLength({ max: 500 })],
  validate,
  ctrl.reviewManualPayment
);

module.exports = router;
