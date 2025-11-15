const express = require('express');
const multer = require('multer');
const path = require('path');
const Mentor = require('../models/Mentor');
const Booking = require('../models/Booking');
const College = require('../models/College');
const { authenticate, authorize } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
// const { cloudinaryUtils } = require('../utils/cloudinary'); // Disabled - using local uploads
const {
  createMentorValidation,
  updateMentorValidation,
  searchMentorsValidation,
  addMentorReviewValidation
} = require('../validators/mentorValidator');

const router = express.Router();

// Configure multer for profile photo upload
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed!'));
  }
});

/**
 * @route   GET /api/mentors/search
 * @desc    Search mentors with filters
 * @access  Public
 */
router.get('/search', searchMentorsValidation, async (req, res) => {
  try {
    const searchParams = req.query;
    const result = await Mentor.searchMentors(searchParams);

    logger.systemEvent('mentor_search', {
      filters: {
        college: searchParams.college,
        course: searchParams.course,
        year: searchParams.year,
        subjects: searchParams.subjects
      },
      resultsCount: result.mentors.length
    });

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'mentor_search', query: req.query });
    res.status(500).json({ 
      error: 'Failed to search mentors' 
    });
  }
});

/**
 * @route   GET /api/mentors/top
 * @desc    Get top-rated mentors
 * @access  Public
 */
router.get('/top', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const topMentors = await Mentor.getTopMentors(parseInt(limit));

    res.json({
      success: true,
      data: topMentors
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'top_mentors' });
    res.status(500).json({ 
      error: 'Failed to fetch top mentors' 
    });
  }
});

/**
 * @route   GET /api/mentors/college/:collegeId
 * @desc    Get mentors by college
 * @access  Public
 */
router.get('/college/:collegeId', async (req, res) => {
  try {
    const { collegeId } = req.params;
    const mentors = await Mentor.getMentorsByCollege(collegeId);

    res.json({
      success: true,
      data: mentors
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'mentors_by_college', 
      collegeId: req.params.collegeId 
    });
    res.status(500).json({ 
      error: 'Failed to fetch mentors by college' 
    });
  }
});

/**
 * @route   GET /api/mentors/:id
 * @desc    Get mentor profile details
 * @access  Public
 */
router.get('/:id', async (req, res) => {
  try {
    const mentor = await Mentor.findById(req.params.id);
      // .populate('user', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
      // .populate('college', 'name state city type rating photos') // TODO: Replace with JOIN
      // .populate('reviews.student', 'profile.name profile.avatar'); // TODO: Replace with JOIN

    if (!mentor) {
      return res.status(404).json({ 
        error: 'Mentor not found' 
      });
    }

    if (!mentor.isActive) {
      return res.status(403).json({ 
        error: 'Mentor profile is not active' 
      });
    }

    // Get mentor's booking statistics
    const bookingStats = await Booking.getBookingStats(mentor._id);

    // Get upcoming sessions (limit 5)
    const upcomingSessions = await Booking.getUpcomingBookings(mentor._id, 'mentor', 5);

    res.json({
      success: true,
      data: {
        mentor,
        bookingStats,
        upcomingSessions
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'mentor_details', 
      mentorId: req.params.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch mentor details' 
    });
  }
});

/**
 * @route   POST /api/mentors/:id/review
 * @desc    Add review to mentor
 * @access  Private (Authenticated users)
 */
router.post('/:id/review',
  authenticate,
  addMentorReviewValidation,
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      if (!mentor.isActive) {
        return res.status(403).json({ 
          error: 'Mentor profile is not active' 
        });
      }

      const { rating, review, subjects = [], sessionType = 'Online' } = req.body;

      await mentor.addReview(req.user._id, rating, review, subjects, sessionType);

      logger.userAction(req.user._id, 'mentor_review_added', {
        mentorId: mentor._id,
        mentorName: mentor.user?.profile?.name || 'Unknown',
        rating: rating
      });

      res.json({
        success: true,
        message: 'Review added successfully',
        data: {
          mentor: {
            id: mentor._id,
            rating: mentor.rating
          }
        }
      });

    } catch (error) {
      if (error.message === 'Student has already reviewed this mentor') {
        return res.status(400).json({ 
          error: error.message 
        });
      }

      logger.errorWithContext(error, { 
        action: 'mentor_review', 
        userId: req.user._id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to add review' 
      });
    }
  }
);

/**
 * @route   POST /api/mentors
 * @desc    Create mentor profile
 * @access  Private (Authenticated users)
 */
router.post('/',
  authenticate,
  createMentorValidation,
  async (req, res) => {
    try {
      // Check if user already has a mentor profile
      const existingMentor = await Mentor.findOne({ user: req.user._id });
      if (existingMentor) {
        return res.status(400).json({ 
          error: 'User already has a mentor profile' 
        });
      }

      // Verify college exists
      const college = await College.findById(req.body.college);
      if (!college) {
        return res.status(404).json({ 
          error: 'College not found' 
        });
      }

      // Check if user is verified (basic verification)
      if (!req.user.isVerified) {
        return res.status(403).json({ 
          error: 'Please verify your email before creating a mentor profile' 
        });
      }

      const mentorData = {
        user_id: req.user._id,
        college_name: req.body.collegeName,
        specialization: req.body.specialization,
        experience_years: req.body.experienceYears || 0,
        subjects: JSON.stringify(req.body.subjects || []),
        hourly_rate: req.body.hourlyRate || 50,
        availability: JSON.stringify(req.body.availability || {}),
        bio: req.body.bio || '',
        is_verified: false,
        is_available: true
      };

      const mentor = await Mentor.create(mentorData);

      // Populate the mentor data for response
      // await mentor.populate([ // TODO: Replace with JOIN
      //   { path: 'user', select: 'profile.name profile.email' },
      //   { path: 'college', select: 'name state city type' }
      // ]);

      logger.userAction(req.user._id, 'mentor_profile_created', {
        mentorId: mentor._id,
        collegeId: mentor.college._id,
        collegeName: mentor.college.name,
        course: mentor.course,
        year: mentor.year
      });

      res.status(201).json({
        success: true,
        message: 'Mentor profile created successfully',
        data: {
          mentor: {
            id: mentor._id,
            user: mentor.user,
            college: mentor.college,
            course: mentor.course,
            year: mentor.year,
            specialization: mentor.specialization,
            rating: mentor.rating,
            pricing: mentor.pricing,
            isVerified: mentor.isVerified,
            isActive: mentor.isActive,
            isAvailable: mentor.isAvailable
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_creation', 
        userId: req.user._id 
      });
      res.status(500).json({ 
        error: 'Failed to create mentor profile' 
      });
    }
  }
);

/**
 * @route   PUT /api/mentors/:id
 * @desc    Update mentor profile
 * @access  Private (Mentor or Admin)
 */
router.put('/:id',
  authenticate,
  updateMentorValidation,
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      // Check if user can update this mentor profile
      const canUpdate = req.user._id.toString() === mentor.user.toString() || 
                       ['admin1', 'admin2', 'admin3'].includes(req.user.role);

      if (!canUpdate) {
        return res.status(403).json({ 
          error: 'Access denied. You can only update your own mentor profile.' 
        });
      }

      // Update mentor data - MySQL style
      const updateData = { ...req.body };
      delete updateData.user;
      delete updateData._id;

      await Mentor.update(mentor.id, updateData);

      logger.userAction(req.user._id, 'mentor_profile_updated', {
        mentorId: mentor._id,
        changes: req.body
      });

      res.json({
        success: true,
        message: 'Mentor profile updated successfully',
        data: {
          mentor: {
            id: mentor._id,
            course: mentor.course,
            year: mentor.year,
            specialization: mentor.specialization,
            rating: mentor.rating,
            pricing: mentor.pricing,
            isAvailable: mentor.isAvailable,
            profile: mentor.profile
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_update', 
        userId: req.user._id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to update mentor profile' 
      });
    }
  }
);

/**
 * @route   PUT /api/mentors/:id/bio
 * @desc    Update mentor bio
 * @access  Private (Mentor only)
 */
router.put('/:id/bio',
  authenticate,
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      // Check if user can update this mentor profile
      if (req.user._id.toString() !== mentor.user.toString()) {
        return res.status(403).json({ 
          error: 'Access denied. You can only update your own profile.' 
        });
      }

      const { bio } = req.body;
      if (!bio || bio.trim().length === 0) {
        return res.status(400).json({ 
          error: 'Bio is required' 
        });
      }

      await Mentor.update(mentor.id, {
        bio: bio.trim()
      });

      logger.userAction(req.user._id, 'mentor_bio_updated', {
        mentorId: mentor._id
      });

      res.json({
        success: true,
        message: 'Bio updated successfully',
        data: {
          bio: mentor.profile.bio
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_bio_update', 
        userId: req.user._id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to update bio' 
      });
    }
  }
);

/**
 * @route   PUT /api/mentors/:id/intro-video
 * @desc    Update mentor intro video
 * @access  Private (Mentor only)
 */
router.put('/:id/intro-video',
  authenticate,
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      // Check if user can update this mentor profile
      if (req.user._id.toString() !== mentor.user.toString()) {
        return res.status(403).json({ 
          error: 'Access denied. You can only update your own profile.' 
        });
      }

      const { introVideo } = req.body;
      if (!introVideo || introVideo.trim().length === 0) {
        return res.status(400).json({ 
          error: 'Intro video URL is required' 
        });
      }

      await Mentor.update(mentor.id, {
        intro_video: introVideo.trim()
      });

      logger.userAction(req.user._id, 'mentor_intro_video_updated', {
        mentorId: mentor._id
      });

      res.json({
        success: true,
        message: 'Intro video updated successfully',
        data: {
          introVideo: mentor.profile.introVideo
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_intro_video_update', 
        userId: req.user._id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to update intro video' 
      });
    }
  }
);

/**
 * @route   POST /api/mentors/:id/upload-photo
 * @desc    Upload mentor profile photo
 * @access  Private (Mentor only)
 */
router.post('/:id/upload-photo',
  authenticate,
  upload.single('photo'),
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      // Check if user can update this mentor profile
      if (req.user._id.toString() !== mentor.user.toString()) {
        return res.status(403).json({ 
          error: 'Access denied. You can only update your own profile.' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ 
          error: 'No photo uploaded' 
        });
      }

      // Upload to Cloudinary
      const uploadResult = await cloudinaryUtils.uploadImage(req.file);
      
      if (!uploadResult.success) {
        return res.status(500).json({ 
          error: 'Failed to upload to cloud storage',
          details: uploadResult.error
        });
      }

      // Delete old photo from Cloudinary if exists
      if (mentor.profile.profilePhoto && mentor.profile.profilePhoto.includes('cloudinary')) {
        const oldPublicId = mentor.profile.profilePhoto.split('/').pop().split('.')[0];
        await cloudinaryUtils.deleteImage(`medipredict/${oldPublicId}`);
      }

      // Update mentor's profile photo with Cloudinary URL
      await Mentor.update(mentor.id, {
        profile_photo: uploadResult.data.secure_url
      });

      logger.userAction(req.user._id, 'mentor_photo_uploaded', {
        mentorId: mentor._id
      });

      res.json({
        success: true,
        message: 'Profile photo uploaded successfully',
        data: {
          photoUrl: uploadResult.data.secure_url,
          cloudinaryData: {
            public_id: uploadResult.data.public_id,
            width: uploadResult.data.width,
            height: uploadResult.data.height,
            format: uploadResult.data.format,
            bytes: uploadResult.data.bytes
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_photo_upload', 
        userId: req.user._id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to upload profile photo' 
      });
    }
  }
);

/**
 * @route   GET /api/mentors
 * @desc    Get all mentors with pagination (Admin only)
 * @access  Private (Admin only)
 */
router.get('/',
  adminAuth(['admin1', 'admin2', 'admin3']),
  logAdminAction('mentors_list_viewed', 'Admin viewed mentors list'),
  async (req, res) => {
    try {
      const { 
        page = 1, 
        limit = 20, 
        college, 
        course, 
        isVerified,
        isActive,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (college) query.college = college;
      if (course) query.course = course;
      if (isVerified !== undefined) query.isVerified = isVerified === 'true';
      if (isActive !== undefined) query.isActive = isActive === 'true';

      // Role-based filtering
      const { adminRole } = req.admin;
      if (adminRole === 'admin3') {
        // Grade 3 can only see basic mentor info
        query.isActive = true;
      }

      // Execute query
      const mentors = await Mentor.find(query)
        // .populate('user', 'email profile.name profile.avatar') // TODO: Replace with JOIN
        // .populate('college', 'name state city type') // TODO: Replace with JOIN
        .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await Mentor.countDocuments(query);

      res.json({
        success: true,
        data: {
          mentors,
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
        action: 'mentors_list', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch mentors' 
      });
    }
  }
);

/**
 * @route   POST /api/mentors/:id/verify
 * @desc    Verify mentor profile (Admin Grade 1+)
 * @access  Private (Admin Grade 1+)
 */
router.post('/:id/verify',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('mentor_verified', 'Admin verified mentor profile'),
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      await Mentor.update(mentor.id, {
        is_verified: true,
        verified_by: req.admin.id,
        verified_at: new Date().toISOString()
      });

      logger.adminAction(req.admin.id, 'mentor_verified', {
        mentorId: mentor._id,
        userId: mentor.user
      });

      res.json({
        success: true,
        message: 'Mentor profile verified successfully',
        data: {
          mentor: {
            id: mentor._id,
            isVerified: mentor.isVerified,
            verifiedAt: mentor.verifiedAt
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_verification', 
        adminId: req.admin.id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to verify mentor profile' 
      });
    }
  }
);

/**
 * @route   DELETE /api/mentors/:id
 * @desc    Delete mentor profile (Admin Grade 2+)
 * @access  Private (Admin Grade 2+)
 */
router.delete('/:id',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('mentor_deleted', 'Admin deleted mentor profile'),
  async (req, res) => {
    try {
      const mentor = await Mentor.findById(req.params.id);

      if (!mentor) {
        return res.status(404).json({ 
          error: 'Mentor not found' 
        });
      }

      // Soft delete - just deactivate
      await Mentor.update(mentor.id, {
        is_active: false,
        is_available: false
      });

      logger.adminAction(req.admin.id, 'mentor_deleted', {
        mentorId: mentor._id,
        userId: mentor.user
      });

      res.json({
        success: true,
        message: 'Mentor profile deactivated successfully'
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'mentor_delete', 
        adminId: req.admin.id, 
        mentorId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to delete mentor profile' 
      });
    }
  }
);

module.exports = router;



