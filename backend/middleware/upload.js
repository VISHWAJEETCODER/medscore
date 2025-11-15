const multer = require('multer');
const path = require('path');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// File filter to allow images, videos, and documents
const fileFilter = (req, file, cb) => {
  // Allowed file types
  const allowedTypes = [
    'image/', // Images: jpg, png, gif, webp
    'video/', // Videos: mp4, avi, mov, webm
    'application/pdf', // PDF documents
    'application/msword', // Word docs
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
    'application/vnd.ms-powerpoint', // PowerPoint
    'application/vnd.openxmlformats-officedocument.presentationml.presentation', // .pptx
    'text/plain', // Text files
    'application/zip', // ZIP files
    'application/x-rar-compressed' // RAR files
  ];
  
  const isAllowed = allowedTypes.some(type => file.mimetype.startsWith(type));
  
  if (isAllowed) {
    cb(null, true);
  } else {
    cb(new Error('File type not allowed! Allowed: Images, Videos, PDF, Documents'), false);
  }
};

// Configure multer
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit for videos
    files: 10 // Allow multiple files
  }
});

// Middleware for single file upload (profile photos)
const uploadSingle = upload.single('photo');

// Middleware for multiple files upload (documents, videos, materials)
const uploadMultiple = upload.array('documents', 10);

// Middleware for video uploads
const uploadVideo = upload.single('video');

// Middleware for material uploads (PDFs, documents)
const uploadMaterial = upload.single('material');

// Error handling middleware
const handleUploadError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files. Maximum is 10 files.' });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ error: 'Unexpected file field.' });
    }
  }
  
  if (err.message.includes('File type not allowed')) {
    return res.status(400).json({ error: err.message });
  }
  
  next(err);
};

module.exports = {
  uploadSingle,
  uploadMultiple,
  uploadVideo,
  uploadMaterial,
  handleUploadError
};
