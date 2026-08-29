const router = require('express').Router();
const { body } = require('express-validator');
const ctrl = require('../controllers/reportController');
const { validate } = require('../middleware/errorHandler');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

router.post(
  '/',
  [
    body('reportedValue').trim().notEmpty().isLength({ max: 4000 }),
    body('reportType').isIn(['link', 'qr', 'message']),
    body('category').optional().isIn(['phishing', 'fake_reward', 'impersonation', 'otp_scam', 'other']),
  ],
  validate,
  ctrl.createReport
);

router.get('/mine', ctrl.listMyReports);

module.exports = router;
