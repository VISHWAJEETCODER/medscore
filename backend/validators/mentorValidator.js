const { body, query, param } = require('express-validator');

// Validation for mentor application
const mentorApplicationValidation = [
  body('college_name')
    .trim()
    .notEmpty()
    .withMessage('College name is required')
    .isLength({ min: 3, max: 255 })
    .withMessage('College name must be between 3 and 255 characters'),
  
  body('specialization')
    .trim()
    .notEmpty()
    .withMessage('Specialization is required')
    .isLength({ max: 255 })
    .withMessage('Specialization too long'),
  
  body('experience_years')
    .optional()
    .isInt({ min: 0, max: 50 })
    .withMessage('Experience years must be between 0 and 50'),
  
  body('subjects')
    .optional()
    .isArray()
    .withMessage('Subjects must be an array'),
  
  body('hourly_rate')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Hourly rate must be a positive number'),
  
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Bio must not exceed 2000 characters')
];

// Validation for creating mentor (alias)
const createMentorValidation = mentorApplicationValidation;

// Validation for updating mentor profile
const updateMentorValidation = [
  body('college_name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 255 })
    .withMessage('College name must be between 3 and 255 characters'),
  
  body('specialization')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Specialization too long'),
  
  body('experience_years')
    .optional()
    .isInt({ min: 0, max: 50 })
    .withMessage('Experience years must be between 0 and 50'),
  
  body('subjects')
    .optional()
    .isArray()
    .withMessage('Subjects must be an array'),
  
  body('hourly_rate')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Hourly rate must be a positive number'),
  
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Bio must not exceed 2000 characters'),
  
  body('is_available')
    .optional()
    .isBoolean()
    .withMessage('Availability must be boolean')
];

// Validation for searching mentors
const searchMentorsValidation = [
  query('query')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query too long'),
  
  query('college_name')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('College name too long'),
  
  query('specialization')
    .optional()
    .trim()
    .isLength({ max: 255 })
    .withMessage('Specialization too long'),
  
  query('minRating')
    .optional()
    .isFloat({ min: 0, max: 5 })
    .withMessage('Min rating must be between 0 and 5'),
  
  query('maxRate')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Max rate must be positive'),
  
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be positive'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
];

// Validation for booking a mentor session
const bookMentorValidation = [
  body('mentor_id')
    .notEmpty()
    .withMessage('Mentor ID is required'),
  
  body('session_date')
    .notEmpty()
    .withMessage('Session date is required')
    .isISO8601()
    .withMessage('Invalid date format'),
  
  body('session_time')
    .notEmpty()
    .withMessage('Session time is required'),
  
  body('duration')
    .optional()
    .isInt({ min: 15, max: 180 })
    .withMessage('Duration must be between 15 and 180 minutes'),
  
  body('subject')
    .trim()
    .notEmpty()
    .withMessage('Subject is required')
    .isLength({ max: 255 })
    .withMessage('Subject too long'),
  
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes too long')
];

// Validation for creating a booking
const createBookingValidation = [
  body('mentor')
    .notEmpty()
    .withMessage('Mentor ID is required'),
  
  body('sessionType')
    .optional()
    .isIn(['Online', 'Offline'])
    .withMessage('Session type must be Online or Offline'),
  
  body('subjects')
    .optional()
    .isArray()
    .withMessage('Subjects must be an array'),
  
  body('sessionDuration')
    .optional()
    .isInt({ min: 30, max: 180 })
    .withMessage('Session duration must be between 30 and 180 minutes'),
  
  body('scheduledDate')
    .notEmpty()
    .withMessage('Scheduled date is required')
    .isISO8601()
    .withMessage('Invalid date format'),
  
  body('scheduledTime.start')
    .notEmpty()
    .withMessage('Start time is required'),
  
  body('scheduledTime.end')
    .notEmpty()
    .withMessage('End time is required')
];

// Validation for cancelling booking
const cancelBookingValidation = [
  body('reason')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Cancellation reason too long')
];

// Validation for updating booking status
const updateBookingValidation = [
  body('status')
    .optional()
    .isIn(['pending', 'confirmed', 'completed', 'cancelled'])
    .withMessage('Invalid status'),
  
  body('meeting_link')
    .optional()
    .trim()
    .isURL()
    .withMessage('Invalid meeting link URL'),
  
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes too long')
];

// Validation for adding mentor review
const addMentorReviewValidation = [
  body('rating')
    .notEmpty()
    .withMessage('Rating is required')
    .isFloat({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5'),
  
  body('review')
    .trim()
    .notEmpty()
    .withMessage('Review is required')
    .isLength({ min: 10, max: 1000 })
    .withMessage('Review must be between 10 and 1000 characters'),
  
  body('booking_id')
    .notEmpty()
    .withMessage('Booking ID is required')
];

module.exports = {
  mentorApplicationValidation,
  createMentorValidation,
  updateMentorValidation,
  searchMentorsValidation,
  bookMentorValidation,
  createBookingValidation,
  updateBookingValidation,
  cancelBookingValidation,
  addMentorReviewValidation
};
