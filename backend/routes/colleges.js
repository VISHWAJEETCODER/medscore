const express = require('express');
const multer = require('multer');
const path = require('path');
const College = require('../models/College');
const CutoffData = require('../models/CutoffData');
const { authenticate, authorize, optionalAuth } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const {
  createCollegeValidation,
  updateCollegeValidation,
  searchCollegesValidation,
  addReviewValidation,
  createCutoffValidation,
  predictCollegesValidation
} = require('../validators/collegeValidator');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|webm/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only images and videos are allowed!'));
  }
});

/**
 * @route   GET /api/colleges/search
 * @desc    Search colleges with filters
 * @access  Public
 */
router.get('/search', searchCollegesValidation, async (req, res) => {
  try {
    const searchParams = req.query;
    const result = await College.searchColleges(searchParams);

    logger.systemEvent('college_search', {
      query: searchParams.query,
      filters: {
        state: searchParams.state,
        city: searchParams.city,
        type: searchParams.type,
        category: searchParams.category
      },
      resultsCount: result.colleges.length
    });

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'college_search', query: req.query });
    res.status(500).json({ 
      error: 'Failed to search colleges' 
    });
  }
});

/**
 * @route   GET /api/colleges/trending
 * @desc    Get trending colleges
 * @access  Public
 */
router.get('/trending', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const trendingColleges = await College.getTrendingColleges(parseInt(limit));

    res.json({
      success: true,
      data: trendingColleges
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'trending_colleges' });
    res.status(500).json({ 
      error: 'Failed to fetch trending colleges' 
    });
  }
});

/**
 * @route   GET /api/colleges/by-state/:state
 * @desc    Get colleges by state
 * @access  Public
 */
router.get('/by-state/:state', async (req, res) => {
  try {
    const { state } = req.params;
    const colleges = await College.getCollegesByState(state);

    res.json({
      success: true,
      data: colleges
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'colleges_by_state', state: req.params.state });
    res.status(500).json({ 
      error: 'Failed to fetch colleges by state' 
    });
  }
});

/**
 * @route   GET /api/colleges/:id
 * @desc    Get college details by ID
 * @access  Public
 */
router.get('/:id', async (req, res) => {
  try {
    const college = await College.findById(req.params.id);
      // .populate('reviews.user', 'profile.name profile.avatar') // TODO: Replace with JOIN
      // .populate('createdBy', 'profile.name') // TODO: Replace with JOIN
      // .populate('updatedBy', 'profile.name'); // TODO: Replace with JOIN

    if (!college) {
      return res.status(404).json({ 
        error: 'College not found' 
      });
    }

    if (!college.isActive) {
      return res.status(403).json({ 
        error: 'College is not active' 
      });
    }

    // Get cutoff data for this college
    const cutoffData = await CutoffData.find({
      college: college._id,
      isVerified: true
    })
    .sort({ year: -1, round: 1 })
    .limit(20)
    .select('year round course quota category gender openingRank closingRank seats');

    res.json({
      success: true,
      data: {
        college,
        cutoffData
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'college_details', collegeId: req.params.id });
    res.status(500).json({ 
      error: 'Failed to fetch college details' 
    });
  }
});

/**
 * @route   POST /api/colleges/:id/review
 * @desc    Add review to college
 * @access  Private (Authenticated users)
 */
router.post('/:id/review',
  authenticate,
  addReviewValidation,
  async (req, res) => {
    try {
      const college = await College.findById(req.params.id);

      if (!college) {
        return res.status(404).json({ 
          error: 'College not found' 
        });
      }

      if (!college.isActive) {
        return res.status(403).json({ 
          error: 'College is not active' 
        });
      }

      const { rating, review, pros = [], cons = [] } = req.body;

      await college.addReview(req.user._id, rating, review, pros, cons);

      logger.userAction(req.user._id, 'college_review_added', {
        collegeId: college._id,
        collegeName: college.name,
        rating: rating
      });

      res.json({
        success: true,
        message: 'Review added successfully',
        data: {
          college: {
            id: college._id,
            name: college.name,
            rating: college.rating
          }
        }
      });

    } catch (error) {
      if (error.message === 'User has already reviewed this college') {
        return res.status(400).json({ 
          error: error.message 
        });
      }

      logger.errorWithContext(error, { 
        action: 'college_review', 
        userId: req.user._id, 
        collegeId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to add review' 
      });
    }
  }
);

/**
 * @route   POST /api/colleges
 * @desc    Create new college (Admin only)
 * @access  Private (Admin Grade 2+)
 */
router.post('/',
  adminAuth(['admin1', 'admin2']),
  createCollegeValidation,
  logAdminAction('college_created', 'Admin created new college'),
  async (req, res) => {
    try {
      // Check if college already exists
      const existingCollege = await College.findOne({
        name: { $regex: new RegExp(req.body.name, 'i') }
      });

      if (existingCollege) {
        return res.status(400).json({ 
          error: 'College with this name already exists' 
        });
      }

      const collegeData = {
        name: req.body.name,
        state: req.body.state,
        city: req.body.city,
        type: req.body.type || 'Government',
        category: req.body.category,
        is_active: true,
        is_verified: false,
        created_by: req.admin.id,
        updated_by: req.admin.id,
        cutoff_data: JSON.stringify(req.body.cutoffData || {}),
        photos: JSON.stringify(req.body.photos || []),
        facilities: req.body.facilities,
        fees: JSON.stringify(req.body.fees || {}),
        ranking: req.body.ranking
      };

      const college = await College.create(collegeData);

      logger.adminAction(req.admin.id, 'college_created', {
        collegeId: college._id,
        collegeName: college.name,
        state: college.state,
        type: college.type
      });

      res.status(201).json({
        success: true,
        message: 'College created successfully',
        data: {
          college: {
            id: college._id,
            name: college.name,
            state: college.state,
            city: college.city,
            type: college.type,
            category: college.category,
            isActive: college.isActive,
            isVerified: college.isVerified
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'college_creation', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to create college' 
      });
    }
  }
);

/**
 * @route   PUT /api/colleges/:id
 * @desc    Update college (Admin only)
 * @access  Private (Admin Grade 2+)
 */
router.put('/:id',
  adminAuth(['admin1', 'admin2']),
  updateCollegeValidation,
  logAdminAction('college_updated', 'Admin updated college details'),
  async (req, res) => {
    try {
      const college = await College.findById(req.params.id);

      if (!college) {
        return res.status(404).json({ 
          error: 'College not found' 
        });
      }

      // Update college data - MySQL style
      const updateData = { ...req.body };
      delete updateData.createdBy;
      delete updateData._id;
      updateData.updated_by = req.admin.id;
      updateData.last_updated = new Date().toISOString();

      await College.update(college.id, updateData);

      logger.adminAction(req.admin.id, 'college_updated', {
        collegeId: college._id,
        collegeName: college.name,
        changes: req.body
      });

      res.json({
        success: true,
        message: 'College updated successfully',
        data: {
          college: {
            id: college._id,
            name: college.name,
            state: college.state,
            city: college.city,
            type: college.type,
            isActive: college.isActive,
            isVerified: college.isVerified
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'college_update', 
        adminId: req.admin.id, 
        collegeId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to update college' 
      });
    }
  }
);

/**
 * @route   DELETE /api/colleges/:id
 * @desc    Delete college (Admin Grade 1 only)
 * @access  Private (Super Admin only)
 */
router.delete('/:id',
  adminAuth(['admin1']),
  logAdminAction('college_deleted', 'Super admin deleted college'),
  async (req, res) => {
    try {
      const college = await College.findById(req.params.id);

      if (!college) {
        return res.status(404).json({ 
          error: 'College not found' 
        });
      }

      // Soft delete - just deactivate
      await College.update(college.id, {
        is_active: false,
        updated_by: req.admin.id
      });

      logger.adminAction(req.admin.id, 'college_deleted', {
        collegeId: college._id,
        collegeName: college.name
      });

      res.json({
        success: true,
        message: 'College deactivated successfully'
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'college_delete', 
        adminId: req.admin.id, 
        collegeId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to delete college' 
      });
    }
  }
);

/**
 * @route   POST /api/colleges/:id/upload-media
 * @desc    Upload photos/videos for college
 * @access  Private (Admin Grade 2+)
 */
router.post('/:id/upload-media',
  adminAuth(['admin1', 'admin2']),
  upload.array('media', 10), // Max 10 files
  logAdminAction('college_media_uploaded', 'Admin uploaded media for college'),
  async (req, res) => {
    try {
      const college = await College.findById(req.params.id);

      if (!college) {
        return res.status(404).json({ 
          error: 'College not found' 
        });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ 
          error: 'No files uploaded' 
        });
      }

      const uploadedMedia = [];

      // MySQL: Update college with media (needs JSON field update)
      const currentPhotos = college.photos ? JSON.parse(college.photos) : [];
      const currentVideos = college.videos ? JSON.parse(college.videos) : [];

      for (const file of req.files) {
        const mediaData = {
          url: `https://example.com/uploads/${file.originalname}`,
          caption: file.originalname,
          uploadedBy: req.admin.id,
          uploadedAt: new Date().toISOString()
        };

        if (file.mimetype.startsWith('image/')) {
          currentPhotos.push(mediaData);
          uploadedMedia.push({ type: 'photo', ...mediaData });
        } else if (file.mimetype.startsWith('video/')) {
          currentVideos.push(mediaData);
          uploadedMedia.push({ type: 'video', ...mediaData });
        }
      }

      await College.update(college.id, {
        photos: JSON.stringify(currentPhotos),
        videos: JSON.stringify(currentVideos),
        updated_by: req.admin.id
      });

      logger.adminAction(req.admin.id, 'college_media_uploaded', {
        collegeId: college._id,
        collegeName: college.name,
        filesCount: req.files.length
      });

      res.json({
        success: true,
        message: 'Media uploaded successfully',
        data: {
          uploadedMedia,
          totalPhotos: college.photos.length,
          totalVideos: college.videos.length
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'college_media_upload', 
        adminId: req.admin.id, 
        collegeId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to upload media' 
      });
    }
  }
);

/**
 * @route   POST /api/colleges/:id/verify
 * @desc    Verify college (Admin Grade 1 only)
 * @access  Private (Super Admin only)
 */
router.post('/:id/verify',
  adminAuth(['admin1']),
  logAdminAction('college_verified', 'Super admin verified college'),
  async (req, res) => {
    try {
      const college = await College.findById(req.params.id);

      if (!college) {
        return res.status(404).json({ 
          error: 'College not found' 
        });
      }

      await College.update(college.id, {
        is_verified: true,
        verified_by: req.admin.id,
        verified_at: new Date().toISOString(),
        updated_by: req.admin.id
      });

      logger.adminAction(req.admin.id, 'college_verified', {
        collegeId: college._id,
        collegeName: college.name
      });

      res.json({
        success: true,
        message: 'College verified successfully',
        data: {
          college: {
            id: college._id,
            name: college.name,
            isVerified: college.isVerified,
            verifiedAt: college.verifiedAt
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'college_verification', 
        adminId: req.admin.id, 
        collegeId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to verify college' 
      });
    }
  }
);

/**
 * @route   GET /api/colleges
 * @desc    Get all colleges with pagination (Admin only)
 * @access  Private (Admin only)
 */
router.get('/',
  adminAuth(['admin1', 'admin2', 'admin3']),
  logAdminAction('colleges_list_viewed', 'Admin viewed colleges list'),
  async (req, res) => {
    try {
      const { 
        page = 1, 
        limit = 20, 
        state, 
        type, 
        isVerified,
        isActive,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (state) query.state = state;
      if (type) query.type = type;
      if (isVerified !== undefined) query.isVerified = isVerified === 'true';
      if (isActive !== undefined) query.isActive = isActive === 'true';

      // Execute query
      const colleges = await College.find(query)
        // .populate('createdBy', 'email profile.name') // TODO: Replace with JOIN
        // .populate('updatedBy', 'email profile.name') // TODO: Replace with JOIN
        .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await College.countDocuments(query);

      res.json({
        success: true,
        data: {
          colleges,
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
        action: 'colleges_list', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch colleges' 
      });
    }
  }
);

module.exports = router;



