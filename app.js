require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const { apiLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const logger = require('./utils/logger');
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const userRoutes = require('./routes/users');
const subscriptionRoutes = require('./routes/subscriptions');
const notificationRoutes = require('./routes/notifications');
const adminRoutes = require('./routes/admin');
const app = express();
// --- Security middleware ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "'unsafe-inline'"],
    },
  },
}));
// NOTE: `origin: '*'` combined with `credentials: true` is invalid per the CORS
// spec (browsers reject it) and unsafe even where it's tolerated - it must
// never be the default. CORS_ORIGIN is required in production; in dev it
// falls back to the Flutter app's usual local dev origins only.
const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
  : ['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:3000'];
if (process.env.NODE_ENV === 'production' && !process.env.CORS_ORIGIN) {
  logger.error('CORS_ORIGIN must be set in production - refusing to start with an open/dev CORS policy.');
  throw new Error('CORS_ORIGIN must be set in production.');
}
app.use(cors({ origin: corsOrigins, credentials: true }));
app.use(compression());
app.use(express.json({ limit: '256kb' })); // small limit: mitigates payload-based DoS
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.set('trust proxy', 1); // needed for correct req.ip behind a load balancer/serverless edge
// Basic XSS/SQLi guard: express-validator + parameterized `pg` queries handle the
// bulk of this; strip null bytes and control chars from string inputs defensively.
app.use((req, res, next) => {
  const clean = (obj) => {
    if (typeof obj === 'string') return obj.replace(/\0/g, '');
    if (Array.isArray(obj)) return obj.map(clean);
    if (obj && typeof obj === 'object') {
      for (const k of Object.keys(obj)) obj[k] = clean(obj[k]);
      return obj;
    }
    return obj;
  };
  if (req.body) req.body = clean(req.body);
  next();
});
app.use('/api', apiLimiter);
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'linkshield-api', time: new Date().toISOString() }));
// Note: the GCash InstaPay QR code is served via the authenticated
// GET /api/subscriptions/payment-qr route (see routes/subscriptions.js), and
// payment-proof screenshots are only readable via the authenticated admin
// endpoint (adminController.getPaymentProof) - neither is exposed statically,
// since proof screenshots may show the customer's GCash account details.
//
// The admin payments-review page itself is just static HTML/JS - it calls the
// authenticated /api/admin/payments endpoints with a bearer token pasted in,
// so serving the page itself doesn't need auth (loading it shows nothing
// without a valid admin token).
app.use('/admin', express.static(path.join(__dirname, 'public', 'admin')));
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/users', userRoutes);
app.use('/api/subscriptions', subscriptionRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/admin', adminRoutes);
// The LinkShield web app (marketing page + in-browser app) - served from the
// same origin as the API so the frontend never has to deal with CORS at all.
app.use(express.static(path.join(__dirname, 'public', 'site')));
app.use(notFound);
app.use(errorHandler);
module.exports = app;
