const multer = require('multer');

// Files are held in memory only, then handed to paymentProofStorageService
// to upload into Supabase Storage. Nothing is written to local disk - on
// Vercel the filesystem is read-only outside /tmp, and /tmp isn't shared
// between invocations, so a locally-saved file would be gone by the time an
// admin tries to review it later.

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp']);

const paymentProofUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB - a phone screenshot fits comfortably
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return cb(new Error('Only JPEG, PNG, or WEBP screenshots are accepted'));
    }
    cb(null, true);
  },
});

module.exports = { paymentProofUpload };
