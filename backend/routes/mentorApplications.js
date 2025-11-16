const express = require('express');
const multer = require('multer');
const path = require('path');
const MentorApplication = require('../models/MentorApplication');
const { authenticate } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');

const router = express.Router();

// Configure multer for document uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only images and documents are allowed!'));
  }
});

/**
 * @route   POST /api/mentor-applications
 * @desc    Submit mentor application
 * @access  Private
 */
router.post('/', authenticate, async (req, res) => {
  try {
    // Check if user already has an application
    const existingApplication = await MentorApplication.findOne({ user_id: req.user._id });
    if (existingApplication) {
      return res.status(400).json({
        success: false,
        message: 'Application already exists. You can only submit one application.'
      });
    }

    const {
      personalInfo,
      education,
      professionalInfo,
      mentorshipInfo,
      applicationDetails
    } = req.body;

    // Validate required fields
    if (!personalInfo?.fullName || !personalInfo?.email || !personalInfo?.phone) {
      return res.status(400).json({
        success: false,
        message: 'Personal information is required'
      });
    }

    if (!education?.college || !education?.course || !education?.graduationYear) {
      return res.status(400).json({
        success: false,
        message: 'Educational information is required'
      });
    }

    if (!mentorshipInfo?.subjects || mentorshipInfo.subjects.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'At least one subject is required'
      });
    }

    if (!applicationDetails?.bio || !applicationDetails?.whyMentor) {
      return res.status(400).json({
        success: false,
        message: 'Bio and motivation are required'
      });
    }

    const applicationData = {
      user_id: req.user._id,
      personalInfo: JSON.stringify(personalInfo),
      education: JSON.stringify(education),
      professionalInfo: JSON.stringify(professionalInfo),
      mentorshipInfo: JSON.stringify(mentorshipInfo),
      applicationDetails: JSON.stringify(applicationDetails),
      status: 'pending'
    };

    const application = await MentorApplication.create(applicationData);

    // Populate the application data
    // await application.populate('user', 'profile.name profile.email'); // TODO: Replace with JOIN

    logger.userAction(req.user._id, 'mentor_application_submitted', {
      applicationId: application._id,
      college: education.college,
      course: education.course
    });

    res.status(201).json({
      success: true,
      message: 'Mentor application submitted successfully',
      data: application
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'submit_mentor_application', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to submit mentor application' 
    });
  }
});

/**
 * @route   GET /api/mentor-applications/my-application
 * @desc    Get user's mentor application
 * @access  Private
 */
router.get('/my-application', authenticate, async (req, res) => {
  try {
    const application = await MentorApplication.findOne({ user_id: req.user._id });
      // .populate('review.reviewedBy', 'profile.name'); // TODO: Replace with JOIN

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'No mentor application found'
      });
    }

    res.json({
      success: true,
      data: application
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'get_my_application', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch mentor application' 
    });
  }
});

/**
 * @route   PUT /api/mentor-applications/my-application
 * @desc    Update user's mentor application
 * @access  Private
 */
router.put('/my-application', authenticate, async (req, res) => {
  try {
    const application = await MentorApplication.findOne({ user_id: req.user._id });

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'No mentor application found'
      });
    }

    // Only allow updates if status is pending or under_review
    if (!['pending', 'under_review'].includes(application.status)) {
      return res.status(400).json({
        success: false,
        message: 'Cannot update application after review has started'
      });
    }

    const {
      personalInfo,
      education,
      professionalInfo,
      mentorshipInfo,
      applicationDetails
    } = req.body;

    // Update fields - prepare update data
    const updateData = {};
    if (personalInfo) updateData.personalInfo = JSON.stringify(personalInfo);
    if (education) updateData.education = JSON.stringify(education);
    if (professionalInfo) updateData.professionalInfo = JSON.stringify(professionalInfo);
    if (mentorshipInfo) updateData.mentorshipInfo = JSON.stringify(mentorshipInfo);
    if (applicationDetails) updateData.applicationDetails = JSON.stringify(applicationDetails);

    await MentorApplication.update(application.id, updateData);

    logger.userAction(req.user._id, 'mentor_application_updated', {
      applicationId: application._id
    });

    res.json({
      success: true,
      message: 'Mentor application updated successfully',
      data: application
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'update_mentor_application', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to update mentor application' 
    });
  }
});

/**
 * @route   POST /api/mentor-applications/:id/upload-document
 * @desc    Upload document for mentor application
 * @access  Private
 */
router.post('/:id/upload-document',
  authenticate,
  upload.single('document'),
  async (req, res) => {
    try {
      const application = await MentorApplication.findById(req.params.id);

      if (!application) {
        return res.status(404).json({
          success: false,
          message: 'Mentor application not found'
        });
      }

      // Check if user owns this application
      if (application.user_id.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Access denied'
        });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'No document uploaded'
        });
      }

      const { documentType, documentName } = req.body;

      if (!documentType || !documentName) {
        return res.status(400).json({
          success: false,
          message: 'Document type and name are required'
        });
      }

      // In production, upload to Cloudinary here
      const documentUrl = `https://example.com/uploads/mentor_app_${application._id}_${Date.now()}.pdf`;

      // MySQL: Update document array - needs custom implementation
      // For now, log and return success
      // await application.addDocument(documentType, documentName, documentUrl);

      logger.userAction(req.user._id, 'mentor_application_document_uploaded', {
        applicationId: application._id,
        documentType: documentType,
        documentName: documentName
      });

      res.json({
        success: true,
        message: 'Document uploaded successfully',
        data: {
          documentType,
          documentName,
          documentUrl
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'upload_application_document', 
        userId: req.user._id,
        applicationId: req.params.id
      });
      res.status(500).json({ 
        error: 'Failed to upload document' 
      });
    }
  }
);

/**
 * @route   GET /api/mentor-applications
 * @desc    Get all mentor applications (Admin only)
 * @access  Private (Admin only)
 */
router.get('/',
  adminAuth(['admin1', 'admin2', 'admin3']),
  logAdminAction('mentor_applications_viewed', 'Admin viewed mentor applications list'),
  async (req, res) => {
    try {
      const {
        status,
        college,
        course,
        subjects,
        languages,
        appliedAfter,
        appliedBefore,
        sortBy = 'appliedAt',
        sortOrder = 'desc',
        page = 1,
        limit = 20
      } = req.query;

      const searchParams = {
        status,
        college,
        course,
        subjects: subjects ? subjects.split(',') : undefined,
        languages: languages ? languages.split(',') : undefined,
        appliedAfter,
        appliedBefore,
        sortBy,
        sortOrder,
        page,
        limit
      };

      const result = await MentorApplication.searchApplications(searchParams);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'get_mentor_applications', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch mentor applications' 
      });
    }
  }
);

/**
 * @route   GET /api/mentor-applications/stats
 * @desc    Get mentor application statistics (Admin only)
 * @access  Private (Admin Grade 1+)
 */
router.get('/stats',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('mentor_applications_stats_viewed', 'Admin viewed mentor application statistics'),
  async (req, res) => {
    try {
      const stats = await MentorApplication.getApplicationStats();

      res.json({
        success: true,
        data: stats
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'get_application_stats', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch application statistics' 
      });
    }
  }
);

/**
 * @route   GET /api/mentor-applications/:id
 * @desc    Get specific mentor application (Admin only)
 * @access  Private (Admin only)
 */
router.get('/:id',
  adminAuth(['admin1', 'admin2', 'admin3']),
  async (req, res) => {
    try {
      const application = await MentorApplication.findById(req.params.id);
        // .populate('user', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
        // .populate('review.reviewedBy', 'profile.name'); // TODO: Replace with JOIN

      if (!application) {
        return res.status(404).json({
          success: false,
          message: 'Mentor application not found'
        });
      }

      res.json({
        success: true,
        data: application
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'get_mentor_application', 
        adminId: req.admin.id,
        applicationId: req.params.id
      });
      res.status(500).json({ 
        error: 'Failed to fetch mentor application' 
      });
    }
  }
);

/**
 * @route   PUT /api/mentor-applications/:id/approve
 * @desc    Approve mentor application (Admin Grade 1+)
 * @access  Private (Admin Grade 1+)
 */
router.put('/:id/approve',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('mentor_application_approved', 'Admin approved mentor application'),
  async (req, res) => {
    try {
      const application = await MentorApplication.findById(req.params.id);

      if (!application) {
        return res.status(404).json({
          success: false,
          message: 'Mentor application not found'
        });
      }

      if (application.status === 'approved') {
        return res.status(400).json({
          success: false,
          message: 'Application is already approved'
        });
      }

      const { reviewNotes, score, feedback } = req.body;

      // Update application - MySQL style
      const updateData = {
        status: 'approved',
        reviewed_by: req.admin.id,
        reviewed_at: new Date().toISOString(),
        review_notes: reviewNotes,
        review_score: score,
        review_feedback: JSON.stringify(feedback)
      };

      await MentorApplication.update(application.id, updateData);

      logger.adminAction(req.admin.id, 'mentor_application_approved', {
        applicationId: application._id,
        userId: application.user,
        college: application.education.college
      });

      res.json({
        success: true,
        message: 'Mentor application approved successfully',
        data: {
          applicationId: application._id,
          status: application.status,
          reviewedAt: application.review.reviewedAt
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'approve_mentor_application', 
        adminId: req.admin.id,
        applicationId: req.params.id
      });
      res.status(500).json({ 
        error: 'Failed to approve mentor application' 
      });
    }
  }
);

/**
 * @route   PUT /api/mentor-applications/:id/reject
 * @desc    Reject mentor application (Admin Grade 1+)
 * @access  Private (Admin Grade 1+)
 */
router.put('/:id/reject',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('mentor_application_rejected', 'Admin rejected mentor application'),
  async (req, res) => {
    try {
      const application = await MentorApplication.findById(req.params.id);

      if (!application) {
        return res.status(404).json({
          success: false,
          message: 'Mentor application not found'
        });
      }

      if (application.status === 'rejected') {
        return res.status(400).json({
          success: false,
          message: 'Application is already rejected'
        });
      }

      const { reviewNotes, feedback, nextSteps } = req.body;

      // Update application - MySQL style
      const updateData = {
        status: 'rejected',
        reviewed_by: req.admin.id,
        reviewed_at: new Date().toISOString(),
        review_notes: reviewNotes,
        review_feedback: JSON.stringify(feedback),
        next_steps: nextSteps
      };

      await MentorApplication.update(application.id, updateData);

      logger.adminAction(req.admin.id, 'mentor_application_rejected', {
        applicationId: application._id,
        userId: application.user,
        college: application.education.college
      });

      res.json({
        success: true,
        message: 'Mentor application rejected',
        data: {
          applicationId: application._id,
          status: application.status,
          reviewedAt: application.review.reviewedAt
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'reject_mentor_application', 
        adminId: req.admin.id,
        applicationId: req.params.id
      });
      res.status(500).json({ 
        error: 'Failed to reject mentor application' 
      });
    }
  }
);

/**
 * @route   PUT /api/mentor-applications/:id/status
 * @desc    Update application status (Admin Grade 1+)
 * @access  Private (Admin Grade 1+)
 */
router.put('/:id/status',
  adminAuth(['admin1', 'admin2']),
  async (req, res) => {
    try {
      const application = await MentorApplication.findById(req.params.id);

      if (!application) {
        return res.status(404).json({
          success: false,
          message: 'Mentor application not found'
        });
      }

      const { status, notes } = req.body;

      if (!['pending', 'under_review', 'on_hold', 'approved', 'rejected'].includes(status)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid status'
        });
      }

      await application.updateStatus(status, req.admin.id, notes);

      logger.adminAction(req.admin.id, 'mentor_application_status_updated', {
        applicationId: application._id,
        newStatus: status,
        userId: application.user
      });

      res.json({
        success: true,
        message: 'Application status updated successfully',
        data: {
          applicationId: application._id,
          status: application.status,
          updatedAt: application.updatedAt
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'update_application_status', 
        adminId: req.admin.id,
        applicationId: req.params.id
      });
      res.status(500).json({ 
        error: 'Failed to update application status' 
      });
    }
  }
);

module.exports = router;
