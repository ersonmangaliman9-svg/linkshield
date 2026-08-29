const router = require('express').Router();
const { body, param, query } = require('express-validator');
const ctrl = require('../controllers/scanController');
const { validate } = require('../middleware/errorHandler');
const { requireAuth } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimiter');

router.use(requireAuth);

router.post(
  '/link',
  scanLimiter,
  [body('url').trim().notEmpty().isLength({ max: 2048 })],
  validate,
  ctrl.scanLink
);

router.post(
  '/qr',
  scanLimiter,
  [body('payload').trim().notEmpty().isLength({ max: 4096 })],
  validate,
  ctrl.scanQr
);

router.post(
  '/message',
  scanLimiter,
  [body('text').trim().notEmpty().isLength({ max: 8000 })],
  validate,
  ctrl.scanMessage
);

router.get(
  '/history',
  [
    query('type').optional().isIn(['link', 'qr', 'message']),
    query('level').optional().isIn(['safe', 'suspicious', 'dangerous']),
    query('page').optional().isInt({ min: 1 }),
    query('pageSize').optional().isInt({ min: 1, max: 100 }),
  ],
  validate,
  ctrl.getHistory
);

router.get('/:id', [param('id').isUUID()], validate, ctrl.getScanDetail);
router.delete('/:id', [param('id').isUUID()], validate, ctrl.deleteScan);

module.exports = router;
