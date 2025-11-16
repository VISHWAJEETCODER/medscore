const express = require('express');
const Booking = require('../models/Booking');
const Mentor = require('../models/Mentor');
const { authenticate, authorize } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const {
  createBookingValidation,
  updateBookingValidation,
  cancelBookingValidation
} = require('../validators/mentorValidator');

const router = express.Router();

/**
 * @route   POST /api/bookings
 * @desc    Create new booking
 * @access  Private (Authenticated users)
 */
router.post('/',
  authenticate,
  createBookingValidation,
  async (req, res) => {
    try {
      const {
        mentor,
        sessionType,
        subjects,
        sessionDuration,
        scheduledDate,
        scheduledTime,
        isRecurring = false,
        recurringPattern,
        meetingDetails
      } = req.body;

      // Verify mentor exists and is available
      const mentorProfile = await Mentor.findById(mentor);
      if (!mentorProfile) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      if (!mentorProfile.isActive || !mentorProfile.isAvailable) {
        return res.status(400).json({ 
          error: 'Mentor is not available for booking' 
        });
      }

      // Check if mentor is verified (optional requirement)
      if (!mentorProfile.isVerified) {
        return res.status(400).json({ 
          error: 'Mentor profile is not verified' 
        });
      }

      // Check mentor availability
      const isAvailable = await Booking.checkAvailability(
        mentor,
        new Date(scheduledDate),
        scheduledTime.start,
        scheduledTime.end
      );

      if (!isAvailable) {
        return res.status(400).json({ 
          error: 'Mentor is not available at the requested time' 
        });
      }

      // Validate date is in the future
      const bookingDate = new Date(scheduledDate);
      if (bookingDate <= new Date()) {
        return res.status(400).json({ 
          error: 'Booking date must be in the future' 
        });
      }

      // Create booking data
      const bookingData = {
        student_id: req.user._id,
        mentor_id: mentor,
        session_type: sessionType,
        subjects: JSON.stringify(subjects || []),
        session_duration: sessionDuration,
        session_date: bookingDate.toISOString().split('T')[0],
        session_time: scheduledTime,
        is_recurring: isRecurring || false,
        recurring_pattern: isRecurring ? JSON.stringify(recurringPattern) : null,
        meeting_details: JSON.stringify(meetingDetails || {}),
        amount: mentorProfile.hourly_rate * (sessionDuration / 60),
        status: 'pending'
      };

      const booking = await Booking.create(bookingData);

      // Populate booking data for response
      // await booking.populate([ // TODO: Replace with JOIN query for MySQL
      //   { path: 'student', select: 'profile.name profile.email' },
      //   { path: 'mentor', select: 'user pricing' },
      //   { path: 'mentor.user', select: 'profile.name profile.email' }
      // ]);

      logger.userAction(req.user._id, 'booking_created', {
        bookingId: booking.bookingId,
        mentorId: mentor,
        sessionType: sessionType,
        scheduledDate: scheduledDate,
        totalAmount: booking.pricing.totalAmount
      });

      res.status(201).json({
        success: true,
        message: 'Booking created successfully. Waiting for mentor confirmation.',
        data: {
          booking: {
            id: booking._id,
            bookingId: booking.bookingId,
            mentor: {
              id: booking.mentor._id,
              name: booking.mentor.user.profile.name,
              hourlyRate: booking.mentor.pricing.hourlyRate
            },
            sessionType: booking.sessionType,
            subjects: booking.subjects,
            sessionDuration: booking.sessionDuration,
            scheduledDate: booking.scheduledDate,
            scheduledTime: booking.scheduledTime,
            pricing: booking.pricing,
            status: booking.status
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'booking_creation', 
        userId: req.user._id 
      });
      res.status(500).json({ 
        error: 'Failed to create booking' 
      });
    }
  }
);

/**
 * @route   GET /api/bookings/my-bookings
 * @desc    Get user's bookings (student or mentor)
 * @access  Private (Authenticated users)
 */
router.get('/my-bookings', authenticate, async (req, res) => {
  try {
    const { 
      type = 'student', // student or mentor
      status, 
      page = 1, 
      limit = 20,
      sortBy = 'scheduledDate',
      sortOrder = 'desc'
    } = req.query;

    // Build query
    const query = {};
    
    if (type === 'student') {
      query.student = req.user._id;
    } else if (type === 'mentor') {
      query.mentor = req.user._id;
    }
    
    if (status) {
      query.status = status;
    }

    // Execute query
    const bookings = await Booking.find(query)
      // .populate(type === 'student' ? 'mentor' : 'student', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
      // .populate(type === 'student' ? 'student' : 'mentor', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
      .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Booking.countDocuments(query);

    res.json({
      success: true,
      data: {
        bookings,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'my_bookings', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch bookings' 
    });
  }
});

/**
 * @route   GET /api/bookings/upcoming
 * @desc    Get upcoming bookings
 * @access  Private (Authenticated users)
 */
router.get('/upcoming', authenticate, async (req, res) => {
  try {
    const { type = 'student', limit = 5 } = req.query;
    
    const upcomingBookings = await Booking.getUpcomingBookings(
      req.user._id, 
      type, 
      parseInt(limit)
    );

    res.json({
      success: true,
      data: upcomingBookings
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'upcoming_bookings', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch upcoming bookings' 
    });
  }
});

/**
 * @route   GET /api/bookings/:id
 * @desc    Get booking details
 * @access  Private (Student, Mentor, or Admin)
 */
router.get('/:id', authenticate, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
      // .populate('student', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
      // .populate('mentor', 'user pricing') // TODO: Replace with JOIN
      // .populate('mentor.user', 'profile.name profile.email profile.avatar'); // TODO: Replace with JOIN

    if (!booking) {
      return res.status(404).json({ 
        error: 'Booking not found' 
      });
    }

    // Check if user can access this booking
    const canAccess = req.user._id.toString() === booking.student._id.toString() ||
                     req.user._id.toString() === booking.mentor.user._id.toString() ||
                     ['admin1', 'admin2', 'admin3'].includes(req.user.role);

    if (!canAccess) {
      return res.status(403).json({ 
        error: 'Access denied' 
      });
    }

    res.json({
      success: true,
      data: booking
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'booking_details', 
      userId: req.user._id, 
      bookingId: req.params.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch booking details' 
    });
  }
});

/**
 * @route   PUT /api/bookings/:id
 * @desc    Update booking (Mentor confirmation, reschedule, etc.)
 * @access  Private (Student, Mentor, or Admin)
 */
router.put('/:id',
  authenticate,
  updateBookingValidation,
  async (req, res) => {
    try {
      const booking = await Booking.findById(req.params.id);

      if (!booking) {
        return res.status(404).json({ 
          error: 'Booking not found' 
        });
      }

      // Check if user can update this booking
      const canUpdate = req.user._id.toString() === booking.student._id.toString() ||
                       req.user._id.toString() === booking.mentor._id.toString() ||
                       ['admin1', 'admin2', 'admin3'].includes(req.user.role);

      if (!canUpdate) {
        return res.status(403).json({ 
          error: 'Access denied' 
        });
      }

      // Handle mentor confirmation
      if (req.body.status === 'confirmed' && booking.status === 'pending') {
        // Only mentor can confirm
        if (req.user._id.toString() !== booking.mentor._id.toString()) {
          return res.status(403).json({ 
            error: 'Only mentor can confirm bookings' 
          });
        }
      }

      // Prepare update data for MySQL
      const updateData = {};
      
      if (req.body.status) {
        updateData.status = req.body.status;
        if (req.body.status === 'completed') {
          updateData.completed_at = new Date().toISOString();
        }
      }

      // Update other fields
      Object.keys(req.body).forEach(key => {
        if (key !== 'status' && key !== '_id') {
          if (key === 'scheduledTime') {
            updateData.session_time = req.body[key];
          } else if (key === 'meetingDetails') {
            updateData.meeting_details = JSON.stringify(req.body[key]);
          } else if (key === 'scheduledDate') {
            updateData.session_date = new Date(req.body[key]).toISOString().split('T')[0];
          } else if (key === 'subjects') {
            updateData.subjects = JSON.stringify(req.body[key]);
          } else {
            updateData[key] = req.body[key];
          }
        }
      });

      await Booking.update(booking.id, updateData);

      logger.userAction(req.user._id, 'booking_updated', {
        bookingId: booking.bookingId,
        changes: req.body,
        newStatus: booking.status
      });

      res.json({
        success: true,
        message: 'Booking updated successfully',
        data: {
          booking: {
            id: booking._id,
            bookingId: booking.bookingId,
            status: booking.status,
            scheduledDate: booking.scheduledDate,
            scheduledTime: booking.scheduledTime,
            meetingDetails: booking.meetingDetails
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'booking_update', 
        userId: req.user._id, 
        bookingId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to update booking' 
      });
    }
  }
);

/**
 * @route   POST /api/bookings/:id/cancel
 * @desc    Cancel booking
 * @access  Private (Student, Mentor, or Admin)
 */
router.post('/:id/cancel',
  authenticate,
  cancelBookingValidation,
  async (req, res) => {
    try {
      const booking = await Booking.findById(req.params.id);

      if (!booking) {
        return res.status(404).json({ 
          error: 'Booking not found' 
        });
      }

      // Check if booking can be cancelled
      if (['completed', 'cancelled'].includes(booking.status)) {
        return res.status(400).json({ 
          error: 'Booking cannot be cancelled' 
        });
      }

      // Check if user can cancel this booking
      const canCancel = req.user._id.toString() === booking.student._id.toString() ||
                       req.user._id.toString() === booking.mentor._id.toString() ||
                       ['admin1', 'admin2', 'admin3'].includes(req.user.role);

      if (!canCancel) {
        return res.status(403).json({ 
          error: 'Access denied' 
        });
      }

      const { reason, refundPolicy = 'full' } = req.body;

      await booking.cancelBooking(req.user._id, reason, refundPolicy);

      logger.userAction(req.user._id, 'booking_cancelled', {
        bookingId: booking.bookingId,
        reason: reason,
        refundPolicy: refundPolicy,
        refundAmount: booking.cancellation.refundAmount
      });

      res.json({
        success: true,
        message: 'Booking cancelled successfully',
        data: {
          booking: {
            id: booking._id,
            bookingId: booking.bookingId,
            status: booking.status,
            cancellation: booking.cancellation
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'booking_cancellation', 
        userId: req.user._id, 
        bookingId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to cancel booking' 
      });
    }
  }
);

/**
 * @route   POST /api/bookings/:id/complete
 * @desc    Complete session
 * @access  Private (Mentor only)
 */
router.post('/:id/complete',
  authenticate,
  async (req, res) => {
    try {
      const booking = await Booking.findById(req.params.id);

      if (!booking) {
        return res.status(404).json({ 
          error: 'Booking not found' 
        });
      }

      // Only mentor can complete session
      if (req.user._id.toString() !== booking.mentor._id.toString()) {
        return res.status(403).json({ 
          error: 'Only mentor can complete sessions' 
        });
      }

      if (booking.status !== 'in-progress') {
        return res.status(400).json({ 
          error: 'Only in-progress sessions can be completed' 
        });
      }

      const { sessionNotes } = req.body;

      await booking.completeSession(sessionNotes);

      logger.userAction(req.user._id, 'session_completed', {
        bookingId: booking.bookingId,
        sessionDuration: booking.sessionDuration,
        mentorEarnings: booking.pricing.mentorEarnings
      });

      res.json({
        success: true,
        message: 'Session completed successfully',
        data: {
          booking: {
            id: booking._id,
            bookingId: booking.bookingId,
            status: booking.status,
            completedAt: booking.completedAt,
            sessionNotes: booking.sessionNotes
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'session_completion', 
        userId: req.user._id, 
        bookingId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to complete session' 
      });
    }
  }
);

/**
 * @route   GET /api/bookings
 * @desc    Get all bookings with filters (Admin only)
 * @access  Private (Admin only)
 */
router.get('/',
  adminAuth(['admin1', 'admin2', 'admin3']),
  logAdminAction('bookings_list_viewed', 'Admin viewed bookings list'),
  async (req, res) => {
    try {
      const { 
        page = 1, 
        limit = 50, 
        status, 
        student, 
        mentor,
        dateFrom,
        dateTo,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (status) query.status = status;
      if (student) query.student = student;
      if (mentor) query.mentor = mentor;
      
      if (dateFrom || dateTo) {
        query.scheduledDate = {};
        if (dateFrom) query.scheduledDate.$gte = new Date(dateFrom);
        if (dateTo) query.scheduledDate.$lte = new Date(dateTo);
      }

      // Execute query
      const bookings = await Booking.find(query)
        // .populate('student', 'profile.name profile.email') // TODO: Replace with JOIN
        // .populate('mentor', 'user') // TODO: Replace with JOIN
        // .populate('mentor.user', 'profile.name profile.email') // TODO: Replace with JOIN
        .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await Booking.countDocuments(query);

      res.json({
        success: true,
        data: {
          bookings,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'bookings_list', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch bookings' 
      });
    }
  }
);

/**
 * @route   GET /api/bookings/stats/summary
 * @desc    Get booking statistics
 * @access  Private (Admin or Mentor)
 */
router.get('/stats/summary', authenticate, async (req, res) => {
  try {
    let stats;
    
    if (['admin1', 'admin2', 'admin3'].includes(req.user.role)) {
      // Admin can see all stats
      stats = await Booking.getBookingStats();
    } else {
      // Users can see their own stats
      const mentor = await Mentor.findOne({ user: req.user._id });
      if (mentor) {
        stats = await Booking.getBookingStats(mentor._id);
      } else {
        stats = await Booking.getBookingStats(null, req.user._id);
      }
    }

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'booking_stats', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch booking statistics' 
    });
  }
});

module.exports = router;



