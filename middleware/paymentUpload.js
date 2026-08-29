const path = require('path');
const fs = require('fs');
const multer = require('multer');

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads', 'payment-proofs');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp']);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // req.user is set by requireAuth, which always runs before this middleware.
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, `${req.user.id}_${Date.now()}${ext}`);
  },
});

const paymentProofUpload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB - a phone screenshot fits comfortably
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return cb(new Error('Only JPEG, PNG, or WEBP screenshots are accepted'));
    }
    cb(null, true);
  },
});

module.exports = { paymentProofUpload, UPLOAD_DIR };
