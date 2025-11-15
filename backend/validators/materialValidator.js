const { body, query, param } = require('express-validator');

// Validation for adding material review
const addMaterialReviewValidation = [
  body('rating')
    .notEmpty()
    .withMessage('Rating is required')
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5'),
  
  body('review')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Review must not exceed 1000 characters'),
  
  body('pros')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Pros must be an array with max 10 items'),
  
  body('cons')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Cons must be an array with max 10 items')
];

// Validation for creating study material
const createMaterialValidation = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ min: 3, max: 255 })
    .withMessage('Title must be between 3 and 255 characters'),
  
  body('subject')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Subject name too long'),
  
  body('type')
    .optional()
    .isIn(['pdf', 'video', 'image', 'document'])
    .withMessage('Type must be pdf, video, image, or document'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  
  body('isPremium')
    .optional()
    .isBoolean()
    .withMessage('Premium flag must be boolean')
];

// Validation for updating study material
const updateMaterialValidation = [
  body('title')
    .optional()
    .trim()
    .isLength({ min: 3, max: 255 })
    .withMessage('Title must be between 3 and 255 characters'),
  
  body('subject')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Subject name too long'),
  
  body('type')
    .optional()
    .isIn(['pdf', 'video', 'image', 'document'])
    .withMessage('Type must be pdf, video, image, or document'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  
  body('isPremium')
    .optional()
    .isBoolean()
    .withMessage('Premium flag must be boolean')
];

// Validation for searching materials
const searchMaterialsValidation = [
  query('query')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query too long'),
  
  query('subject')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Subject name too long'),
  
  query('type')
    .optional()
    .isIn(['pdf', 'video', 'image', 'document'])
    .withMessage('Invalid material type'),
  
  query('isPremium')
    .optional()
    .isBoolean()
    .withMessage('Premium filter must be boolean'),
  
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be positive'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
];

// Validation for creating purchase
const createPurchaseValidation = [
  body('materialId')
    .notEmpty()
    .withMessage('Material ID is required'),
  
  body('paymentMethod')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Payment method name too long')
];

// Validation for processing refund
const processRefundValidation = [
  body('reason')
    .trim()
    .notEmpty()
    .withMessage('Refund reason is required')
    .isLength({ min: 10, max: 500 })
    .withMessage('Refund reason must be between 10 and 500 characters')
];

module.exports = {
  addMaterialReviewValidation,
  createMaterialValidation,
  updateMaterialValidation,
  searchMaterialsValidation,
  createPurchaseValidation,
  processRefundValidation
};