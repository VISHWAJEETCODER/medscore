const express = require('express');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const StudyMaterial = require('../models/StudyMaterial');
const Purchase = require('../models/Purchase');
const { authenticate, authorize } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const {
  addMaterialReviewValidation,
  createMaterialValidation,
  updateMaterialValidation,
  searchMaterialsValidation
} = require('../validators/materialValidator');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { 
    fileSize: 50 * 1024 * 1024, // 50MB
    files: 10 // Max 10 files
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx|ppt|pptx|jpg|jpeg|png|mp4|mp3|wav/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Invalid file type. Only PDF, DOC, PPT, images, videos, and audio files are allowed.'));
  }
});

// Middleware to handle validation results
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

/**
 * @route   GET /api/materials/search
 * @desc    Search study materials with filters
 * @access  Public
 */
router.get('/search', searchMaterialsValidation, validate, async (req, res) => {
  try {
    const searchParams = req.query;
    const result = await StudyMaterial.searchMaterials(searchParams);

    logger.systemEvent('material_search', {
      query: searchParams.query,
      filters: {
        category: searchParams.category,
        subject: searchParams.subject,
        course: searchParams.course,
        difficulty: searchParams.difficulty
      },
      resultsCount: result.materials.length
    });

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'material_search', query: req.query });
    res.status(500).json({ 
      error: 'Failed to search materials' 
    });
  }
});

/**
 * @route   GET /api/materials/trending
 * @desc    Get trending study materials
 * @access  Public
 */
router.get('/trending', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const trendingMaterials = await StudyMaterial.getTrendingMaterials(parseInt(limit));

    res.json({
      success: true,
      data: trendingMaterials
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'trending_materials' });
    res.status(500).json({ 
      error: 'Failed to fetch trending materials' 
    });
  }
});

/**
 * @route   GET /api/materials/featured
 * @desc    Get featured study materials
 * @access  Public
 */
router.get('/featured', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const featuredMaterials = await StudyMaterial.getFeaturedMaterials(parseInt(limit));

    res.json({
      success: true,
      data: featuredMaterials
    });

  } catch (error) {
    logger.errorWithContext(error, { action: 'featured_materials' });
    res.status(500).json({ 
      error: 'Failed to fetch featured materials' 
    });
  }
});

/**
 * @route   GET /api/materials/creator/:creatorId
 * @desc    Get materials by creator
 * @access  Public
 */
router.get('/creator/:creatorId', async (req, res) => {
  try {
    const { creatorId } = req.params;
    const { limit = 20 } = req.query;
    
    const materials = await StudyMaterial.getMaterialsByCreator(creatorId, parseInt(limit));

    res.json({
      success: true,
      data: materials
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'materials_by_creator', 
      creatorId: req.params.creatorId 
    });
    res.status(500).json({ 
      error: 'Failed to fetch materials by creator' 
    });
  }
});

/**
 * @route   GET /api/materials/:id
 * @desc    Get material details
 * @access  Public
 */
router.get('/:id', async (req, res) => {
  try {
    const material = await StudyMaterial.findById(req.params.id);
      // .populate('creator', 'profile.name profile.avatar') // TODO: Replace with JOIN
      // .populate('college', 'name state city type') // TODO: Replace with JOIN
      // .populate('reviews.user', 'profile.name profile.avatar'); // TODO: Replace with JOIN

    if (!material) {
      return res.status(404).json({ 
        error: 'Material not found' 
      });
    }

    if (!material.isActive || material.status !== 'published') {
      return res.status(403).json({ 
        error: 'Material is not available' 
      });
    }

    // Increment view count
    await material.incrementViews();

    // Check if user has purchased this material
    let hasPurchased = false;
    let userPurchase = null;
    
    if (req.user) {
      userPurchase = await Purchase.hasPurchased(req.user._id, material._id);
      hasPurchased = !!userPurchase;
    }

    res.json({
      success: true,
      data: {
        material,
        hasPurchased,
        userPurchase: userPurchase ? {
          id: userPurchase._id,
          purchaseId: userPurchase.purchaseId,
          purchasedAt: userPurchase.completedAt,
          downloadCount: userPurchase.download.downloadCount,
          maxDownloads: userPurchase.download.maxDownloads
        } : null
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'material_details', 
      materialId: req.params.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch material details' 
    });
  }
});

/**
 * @route   POST /api/materials/:id/review
 * @desc    Add review to material
 * @access  Private (Authenticated users who purchased)
 */
router.post('/:id/review',
  authenticate,
  addMaterialReviewValidation,
  validate,
  async (req, res) => {
    try {
      const material = await StudyMaterial.findById(req.params.id);

      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      if (!material.isActive || material.status !== 'published') {
        return res.status(403).json({ 
          error: 'Material is not available' 
        });
      }

      // Check if user has purchased this material
      const purchase = await Purchase.hasPurchased(req.user._id, material._id);
      if (!purchase) {
        return res.status(403).json({ 
          error: 'You must purchase this material before reviewing it' 
        });
      }

      const { rating, review, pros = [], cons = [] } = req.body;

      await material.addReview(req.user._id, rating, review, pros, cons);

      logger.userAction(req.user._id, 'material_review_added', {
        materialId: material._id,
        materialTitle: material.title,
        rating: rating
      });

      res.json({
        success: true,
        message: 'Review added successfully',
        data: {
          material: {
            id: material._id,
            title: material.title,
            rating: material.rating
          }
        }
      });

    } catch (error) {
      if (error.message === 'User has already reviewed this material') {
        return res.status(400).json({ 
          error: error.message 
        });
      }

      logger.errorWithContext(error, { 
        action: 'material_review', 
        userId: req.user._id, 
        materialId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to add review' 
      });
    }
  }
);

/**
 * @route   POST /api/materials
 * @desc    Create new study material
 * @access  Private (Authenticated users)
 */
router.post('/',
  authenticate,
  createMaterialValidation,
  validate,
  async (req, res) => {
    try {
      // Check if user is verified
      if (!req.user.isVerified) {
        return res.status(403).json({ 
          error: 'Please verify your email before uploading materials' 
        });
      }

      const materialData = {
        uploaded_by: req.user._id,
        creator_id: req.user._id,
        title: req.body.title,
        subject: req.body.subject,
        type: req.body.type || 'pdf',
        description: req.body.description,
        is_premium: req.body.isPremium || false,
        file_path: req.body.filePath || '',
        status: 'pending'
      };

      const material = await StudyMaterial.create(materialData);

      // Populate the material data for response
      // await material.populate([ // TODO: Replace with JOIN
      //   { path: 'creator', select: 'profile.name profile.email' },
      //   { path: 'college', select: 'name state city type' }
      // ]);

      logger.userAction(req.user._id, 'material_created', {
        materialId: material._id,
        title: material.title,
        category: material.category,
        subject: material.subject,
        price: material.pricing.price
      });

      res.status(201).json({
        success: true,
        message: 'Material created successfully. It will be reviewed before publishing.',
        data: {
          material: {
            id: material._id,
            title: material.title,
            category: material.category,
            subject: material.subject,
            course: material.course,
            pricing: material.pricing,
            status: material.status,
            createdAt: material.createdAt
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'material_creation', 
        userId: req.user._id 
      });
      res.status(500).json({ 
        error: 'Failed to create material' 
      });
    }
  }
);

/**
 * @route   PUT /api/materials/:id
 * @desc    Update study material
 * @access  Private (Creator or Admin)
 */
router.put('/:id',
  authenticate,
  updateMaterialValidation,
  validate,
  async (req, res) => {
    try {
      const material = await StudyMaterial.findById(req.params.id);

      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      // Check if user can update this material
      const canUpdate = req.user._id.toString() === material.creator.toString() || 
                       ['admin1', 'admin2', 'admin3'].includes(req.user.role);

      if (!canUpdate) {
        return res.status(403).json({ 
          error: 'Access denied. You can only update your own materials.' 
        });
      }

      // Update material data - MySQL style
      const updateData = { ...req.body };
      delete updateData.creator;
      delete updateData._id;

      // Reset status to pending if significant changes made
      if (req.body.title || req.body.description || req.body.pricing) {
        updateData.status = 'pending';
      }

      await StudyMaterial.update(material.id, updateData);

      logger.userAction(req.user._id, 'material_updated', {
        materialId: material._id,
        title: material.title,
        changes: req.body
      });

      res.json({
        success: true,
        message: 'Material updated successfully',
        data: {
          material: {
            id: material._id,
            title: material.title,
            status: material.status,
            updatedAt: material.updatedAt
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'material_update', 
        userId: req.user._id, 
        materialId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to update material' 
      });
    }
  }
);

/**
 * @route   POST /api/materials/:id/upload-files
 * @desc    Upload files for study material
 * @access  Private (Creator only)
 */
router.post('/:id/upload-files',
  authenticate,
  upload.array('files', 10),
  async (req, res) => {
    try {
      const material = await StudyMaterial.findById(req.params.id);

      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      // Check if user can upload files for this material
      if (req.user._id.toString() !== material.creator.toString()) {
        return res.status(403).json({ 
          error: 'Access denied. You can only upload files for your own materials.' 
        });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ 
          error: 'No files uploaded' 
        });
      }

      const uploadedFiles = [];

      // MySQL: Update files array (needs JSON field update)
      const currentFiles = material.files ? JSON.parse(material.files) : [];

      for (const file of req.files) {
        const fileUrl = `https://example.com/uploads/materials/${material.id}/${file.originalname}`;
        
        const fileData = {
          name: file.originalname,
          originalName: file.originalname,
          url: fileUrl,
          size: file.size,
          type: path.extname(file.originalname).substring(1),
          thumbnail: file.mimetype.startsWith('image/') ? fileUrl : null,
          isPreview: false,
          uploadedAt: new Date().toISOString()
        };

        currentFiles.push(fileData);
        uploadedFiles.push(fileData);
      }

      // Reset status to pending after file upload
      await StudyMaterial.update(material.id, {
        files: JSON.stringify(currentFiles),
        status: 'pending'
      });

      logger.userAction(req.user._id, 'material_files_uploaded', {
        materialId: material._id,
        filesCount: req.files.length
      });

      res.json({
        success: true,
        message: 'Files uploaded successfully',
        data: {
          uploadedFiles,
          totalFiles: material.files.length,
          status: material.status
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'material_file_upload', 
        userId: req.user._id, 
        materialId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to upload files' 
      });
    }
  }
);

/**
 * @route   GET /api/materials
 * @desc    Get all materials with pagination (Admin only)
 * @access  Private (Admin only)
 */
router.get('/',
  adminAuth(['admin1', 'admin2', 'admin3']),
  logAdminAction('materials_list_viewed', 'Admin viewed materials list'),
  async (req, res) => {
    try {
      const { 
        page = 1, 
        limit = 20, 
        status, 
        category, 
        creator,
        isVerified,
        isActive,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (status) query.status = status;
      if (category) query.category = category;
      if (creator) query.creator = creator;
      if (isVerified !== undefined) query.isVerified = isVerified === 'true';
      if (isActive !== undefined) query.isActive = isActive === 'true';

      // Role-based filtering
      const { adminRole } = req.admin;
      if (adminRole === 'admin3') {
        // Grade 3 can only see published materials
        query.status = 'published';
      }

      // Execute query
      const materials = await StudyMaterial.find(query)
        // .populate('creator', 'email profile.name profile.avatar') // TODO: Replace with JOIN
        // .populate('college', 'name state city type') // TODO: Replace with JOIN
        .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await StudyMaterial.countDocuments(query);

      res.json({
        success: true,
        data: {
          materials,
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
        action: 'materials_list', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch materials' 
      });
    }
  }
);

/**
 * @route   POST /api/materials/:id/approve
 * @desc    Approve material for publishing (Admin Grade 2+)
 * @access  Private (Admin Grade 2+)
 */
router.post('/:id/approve',
  adminAuth(['admin1', 'admin2']),
  logAdminAction('material_approved', 'Admin approved material for publishing'),
  async (req, res) => {
    try {
      const material = await StudyMaterial.findById(req.params.id);

      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      if (material.status !== 'pending') {
        return res.status(400).json({ 
          error: 'Material is not in pending status' 
        });
      }

      await StudyMaterial.update(material.id, {
        status: 'published',
        is_verified: true,
        verified_by: req.admin.id,
        verified_at: new Date().toISOString(),
        published_at: new Date().toISOString()
      });

      logger.adminAction(req.admin.id, 'material_approved', {
        materialId: material._id,
        title: material.title,
        creatorId: material.creator
      });

      res.json({
        success: true,
        message: 'Material approved and published successfully',
        data: {
          material: {
            id: material._id,
            title: material.title,
            status: material.status,
            publishedAt: material.publishedAt
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'material_approval', 
        adminId: req.admin.id, 
        materialId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to approve material' 
      });
    }
  }
);

/**
 * @route   POST /api/materials/:id/reject
 * @desc    Reject material (Admin Grade 2+)
 * @access  Private (Admin Grade 2+)
 */
router.post('/:id/reject',
  adminAuth(['admin1', 'admin2']),
  body('reason').trim().isLength({ min: 10, max: 500 }).withMessage('Rejection reason must be 10-500 characters'),
  validate,
  logAdminAction('material_rejected', 'Admin rejected material'),
  async (req, res) => {
    try {
      const material = await StudyMaterial.findById(req.params.id);

      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      if (material.status !== 'pending') {
        return res.status(400).json({ 
          error: 'Material is not in pending status' 
        });
      }

      await StudyMaterial.update(material.id, {
        status: 'rejected',
        rejection_reason: req.body.reason
      });

      logger.adminAction(req.admin.id, 'material_rejected', {
        materialId: material._id,
        title: material.title,
        creatorId: material.creator,
        reason: req.body.reason
      });

      res.json({
        success: true,
        message: 'Material rejected successfully',
        data: {
          material: {
            id: material._id,
            title: material.title,
            status: material.status,
            rejectionReason: material.rejectionReason
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'material_rejection', 
        adminId: req.admin.id, 
        materialId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to reject material' 
      });
    }
  }
);

/**
 * @route   DELETE /api/materials/:id
 * @desc    Delete material (Creator or Admin Grade 2+)
 * @access  Private
 */
router.delete('/:id',
  authenticate,
  async (req, res) => {
    try {
      const material = await StudyMaterial.findById(req.params.id);

      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      // Check if user can delete this material
      const canDelete = req.user._id.toString() === material.creator.toString() || 
                       ['admin1', 'admin2'].includes(req.user.role);

      if (!canDelete) {
        return res.status(403).json({ 
          error: 'Access denied. You can only delete your own materials.' 
        });
      }

      // Soft delete - just deactivate
      await StudyMaterial.update(material.id, {
        is_active: false,
        status: 'archived'
      });

      logger.userAction(req.user._id, 'material_deleted', {
        materialId: material._id,
        title: material.title
      });

      res.json({
        success: true,
        message: 'Material deleted successfully'
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'material_delete', 
        userId: req.user._id, 
        materialId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to delete material' 
      });
    }
  }
);

module.exports = router;