const { body, query, param } = require('express-validator');

// Validation for creating a new college
const createCollegeValidation = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('College name is required')
    .isLength({ min: 3, max: 255 })
    .withMessage('College name must be between 3 and 255 characters'),
  
  body('state')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('State name must not exceed 100 characters'),
  
  body('type')
    .optional()
    .isIn(['Government', 'Private', 'Deemed'])
    .withMessage('Type must be Government, Private, or Deemed'),
  
  body('ranking')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Ranking must be a positive integer'),
  
  body('facilities')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Facilities description too long')
];

// Validation for updating college
const updateCollegeValidation = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 255 })
    .withMessage('College name must be between 3 and 255 characters'),
  
  body('state')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('State name must not exceed 100 characters'),
  
  body('type')
    .optional()
    .isIn(['Government', 'Private', 'Deemed'])
    .withMessage('Type must be Government, Private, or Deemed'),
  
  body('ranking')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Ranking must be a positive integer')
];

// Validation for create mentor validation (alias for compatibility)
const createMentorValidation = updateCollegeValidation;

// Validation for searching colleges
const searchCollegesValidation = [
  query('query')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query too long'),
  
  query('state')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('State name too long'),
  
  query('type')
    .optional()
    .isIn(['Government', 'Private', 'Deemed'])
    .withMessage('Invalid college type'),
  
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
];

// Validation for adding review
const addReviewValidation = [
  body('rating')
    .notEmpty()
    .withMessage('Rating is required')
    .isFloat({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5'),
  
  body('review')
    .trim()
    .notEmpty()
    .withMessage('Review text is required')
    .isLength({ min: 10, max: 1000 })
    .withMessage('Review must be between 10 and 1000 characters'),
  
  body('pros')
    .optional()
    .isArray()
    .withMessage('Pros must be an array'),
  
  body('cons')
    .optional()
    .isArray()
    .withMessage('Cons must be an array')
];

// Validation for creating cutoff data
const createCutoffValidation = [
  body('college')
    .notEmpty()
    .withMessage('College ID is required'),
  
  body('year')
    .notEmpty()
    .withMessage('Year is required')
    .isInt({ min: 2015, max: 2030 })
    .withMessage('Year must be between 2015 and 2030'),
  
  body('round')
    .notEmpty()
    .withMessage('Round is required')
    .isInt({ min: 1, max: 4 })
    .withMessage('Round must be between 1 and 4'),
  
  body('course')
    .trim()
    .notEmpty()
    .withMessage('Course is required'),
  
  body('quota')
    .optional()
    .isIn(['All India', 'State', 'Management', 'NRI'])
    .withMessage('Invalid quota type'),
  
  body('category')
    .optional()
    .isIn(['General', 'OBC', 'SC', 'ST', 'EWS'])
    .withMessage('Invalid category'),
  
  body('openingRank')
    .notEmpty()
    .withMessage('Opening rank is required')
    .isInt({ min: 1 })
    .withMessage('Opening rank must be positive'),
  
  body('closingRank')
    .notEmpty()
    .withMessage('Closing rank is required')
    .isInt({ min: 1 })
    .withMessage('Closing rank must be positive')
];

// Validation for college prediction
const predictCollegesValidation = [
  body('rank')
    .notEmpty()
    .withMessage('Rank is required')
    .isInt({ min: 1 })
    .withMessage('Rank must be a positive integer'),
  
  body('category')
    .optional()
    .isIn(['General', 'OBC', 'SC', 'ST', 'EWS'])
    .withMessage('Invalid category'),
  
  body('quota')
    .optional()
    .isIn(['All India', 'State', 'Management', 'NRI'])
    .withMessage('Invalid quota type'),
  
  body('state')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('State name too long')
];

module.exports = {
  createCollegeValidation,
  updateCollegeValidation,
  searchCollegesValidation,
  addReviewValidation,
  createCutoffValidation,
  predictCollegesValidation
};
