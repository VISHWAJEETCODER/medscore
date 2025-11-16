const express = require('express');
const { body, validationResult } = require('express-validator');
const StudyMaterial = require('../models/StudyMaterial');
const Purchase = require('../models/Purchase');
const { authenticate, authorize } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const {
  createPurchaseValidation,
  processRefundValidation
} = require('../validators/materialValidator');

const router = express.Router();

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
 * @route   POST /api/purchases
 * @desc    Create new purchase
 * @access  Private (Authenticated users)
 */
router.post('/',
  authenticate,
  createPurchaseValidation,
  validate,
  async (req, res) => {
    try {
      const { materialId, paymentMethod = 'razorpay' } = req.body;

      // Get material details
      const material = await StudyMaterial.findById(materialId);
      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      if (!material.isActive || material.status !== 'published') {
        return res.status(400).json({ 
          error: 'Material is not available for purchase' 
        });
      }

      // Check if user already purchased this material
      const existingPurchase = await Purchase.hasPurchased(req.user._id, materialId);
      if (existingPurchase) {
        return res.status(400).json({ 
          error: 'You have already purchased this material' 
        });
      }

      // Don't allow creators to buy their own materials
      if (material.creator.toString() === req.user._id.toString()) {
        return res.status(400).json({ 
          error: 'You cannot purchase your own material' 
        });
      }

      // Calculate pricing
      const originalPrice = material.pricing && material.pricing.isFree ? 0 : (material.effectivePrice || material.price || 0);
      
      const purchaseData = {
        buyer_id: req.user._id,
        seller_id: material.creator_id || material.uploaded_by,
        material_id: materialId,
        amount: originalPrice,
        currency: 'INR',
        payment_method: paymentMethod,
        status: originalPrice === 0 ? 'completed' : 'pending',
        razorpay_payment_id: originalPrice === 0 ? 'FREE_MATERIAL' : null
      };

      const purchase = await Purchase.create(purchaseData);

      // For free materials, complete the purchase immediately
      if (originalPrice === 0) {
        await purchase.completePurchase({
          paidAt: new Date(),
          transactionId: 'FREE_' + purchase.purchaseId
        });

        // Increment material download stats
        await material.incrementDownloads();
      }

      // Populate purchase data for response
      // await purchase.populate([ // TODO: Replace with JOIN
      //   { path: 'buyer', select: 'profile.name profile.email' },
      //   { path: 'seller', select: 'profile.name profile.email' },
      //   { path: 'material', select: 'title category subject pricing' }
      // ]);

      logger.userAction(req.user._id, 'purchase_created', {
        purchaseId: purchase.purchaseId,
        materialId: materialId,
        materialTitle: material.title,
        amount: purchase.pricing.finalPrice,
        paymentMethod: paymentMethod
      });

      res.status(201).json({
        success: true,
        message: originalPrice === 0 ? 'Free material added to your library' : 'Purchase created successfully',
        data: {
          purchase: {
            id: purchase._id,
            purchaseId: purchase.purchaseId,
            material: purchase.material,
            pricing: purchase.pricing,
            status: purchase.status,
            payment: purchase.payment,
            createdAt: purchase.createdAt
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'purchase_creation', 
        userId: req.user._id 
      });
      res.status(500).json({ 
        error: 'Failed to create purchase' 
      });
    }
  }
);

/**
 * @route   GET /api/purchases/my-purchases
 * @desc    Get user's purchases
 * @access  Private (Authenticated users)
 */
router.get('/my-purchases', authenticate, async (req, res) => {
  try {
    const { 
      status, 
      page = 1, 
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    // Build query
    const query = { buyer: req.user._id };
    
    if (status) {
      query.status = status;
    }

    // Execute query
    const purchases = await Purchase.find(query)
      // .populate('seller', 'profile.name profile.avatar') // TODO: Replace with JOIN
      // .populate('material', 'title category subject pricing') // TODO: Replace with JOIN
      .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Purchase.countDocuments(query);

    res.json({
      success: true,
      data: {
        purchases,
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
      action: 'my_purchases', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch purchases' 
    });
  }
});

/**
 * @route   GET /api/purchases/my-sales
 * @desc    Get user's sales (for creators)
 * @access  Private (Authenticated users)
 */
router.get('/my-sales', authenticate, async (req, res) => {
  try {
    const { 
      status, 
      page = 1, 
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    // Build query
    const query = { seller: req.user._id };
    
    if (status) {
      query.status = status;
    }

    // Execute query
    const sales = await Purchase.find(query)
      // .populate('buyer', 'profile.name profile.avatar') // TODO: Replace with JOIN
      // .populate('material', 'title category subject pricing') // TODO: Replace with JOIN
      .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Purchase.countDocuments(query);

    res.json({
      success: true,
      data: {
        sales,
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
      action: 'my_sales', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch sales' 
    });
  }
});

/**
 * @route   GET /api/purchases/:id
 * @desc    Get purchase details
 * @access  Private (Buyer, Seller, or Admin)
 */
router.get('/:id', authenticate, async (req, res) => {
  try {
    const purchase = await Purchase.findById(req.params.id);
      // .populate('buyer', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
      // .populate('seller', 'profile.name profile.email profile.avatar') // TODO: Replace with JOIN
      // .populate('material', 'title category subject pricing files'); // TODO: Replace with JOIN

    if (!purchase) {
      return res.status(404).json({ 
        error: 'Purchase not found' 
      });
    }

    // Check if user can access this purchase
    const canAccess = req.user._id.toString() === purchase.buyer._id.toString() ||
                     req.user._id.toString() === purchase.seller._id.toString() ||
                     ['admin1', 'admin2', 'admin3'].includes(req.user.role);

    if (!canAccess) {
      return res.status(403).json({ 
        error: 'Access denied' 
      });
    }

    res.json({
      success: true,
      data: purchase
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'purchase_details', 
      userId: req.user._id, 
      purchaseId: req.params.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch purchase details' 
    });
  }
});

/**
 * @route   POST /api/purchases/:id/download
 * @desc    Record download and get download links
 * @access  Private (Purchaser only)
 */
router.post('/:id/download',
  authenticate,
  async (req, res) => {
    try {
      const purchase = await Purchase.findById(req.params.id);

      if (!purchase) {
        return res.status(404).json({ 
          error: 'Purchase not found' 
        });
      }

      // Check if user is the buyer
      if (req.user._id.toString() !== purchase.buyer._id.toString()) {
        return res.status(403).json({ 
          error: 'Access denied. Only the purchaser can download.' 
        });
      }

      // Check if purchase is completed
      if (purchase.status !== 'completed') {
        return res.status(400).json({ 
          error: 'Purchase is not completed yet' 
        });
      }

      // Check if access is active
      if (!purchase.access.isActive) {
        return res.status(403).json({ 
          error: 'Download access has expired' 
        });
      }

      // Record download
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';
      
      await purchase.recordDownload(ipAddress, userAgent);

      // Get material files
      const material = await StudyMaterial.findById(purchase.material);
      if (!material) {
        return res.status(404).json({ 
          error: 'Material not found' 
        });
      }

      // Increment material download count
      await material.incrementDownloads();

      logger.userAction(req.user._id, 'material_downloaded', {
        purchaseId: purchase.purchaseId,
        materialId: material._id,
        materialTitle: material.title,
        downloadCount: purchase.download.downloadCount
      });

      res.json({
        success: true,
        message: 'Download recorded successfully',
        data: {
          purchase: {
            id: purchase._id,
            purchaseId: purchase.purchaseId,
            downloadCount: purchase.download.downloadCount,
            maxDownloads: purchase.download.maxDownloads,
            remainingDownloads: purchase.download.maxDownloads - purchase.download.downloadCount
          },
          material: {
            id: material._id,
            title: material.title,
            files: material.files.map(file => ({
              name: file.name,
              url: file.url,
              type: file.type,
              size: file.size
            }))
          }
        }
      });

    } catch (error) {
      if (error.message === 'Maximum download limit reached') {
        return res.status(400).json({ 
          error: error.message 
        });
      }

      logger.errorWithContext(error, { 
        action: 'material_download', 
        userId: req.user._id, 
        purchaseId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to record download' 
      });
    }
  }
);

/**
 * @route   POST /api/purchases/:id/refund
 * @desc    Request refund for purchase
 * @access  Private (Buyer or Admin)
 */
router.post('/:id/refund',
  authenticate,
  processRefundValidation,
  validate,
  async (req, res) => {
    try {
      const purchase = await Purchase.findById(req.params.id);

      if (!purchase) {
        return res.status(404).json({ 
          error: 'Purchase not found' 
        });
      }

      // Check if user can request refund
      const canRefund = req.user._id.toString() === purchase.buyer._id.toString() ||
                       ['admin1', 'admin2'].includes(req.user.role);

      if (!canRefund) {
        return res.status(403).json({ 
          error: 'Access denied' 
        });
      }

      // Check if purchase can be refunded
      if (purchase.status !== 'completed') {
        return res.status(400).json({ 
          error: 'Only completed purchases can be refunded' 
        });
      }

      if (purchase.refund.status !== 'none') {
        return res.status(400).json({ 
          error: 'Refund has already been processed for this purchase' 
        });
      }

      const { amount, reason } = req.body;

      await purchase.processRefund(amount, reason);

      logger.userAction(req.user._id, 'refund_processed', {
        purchaseId: purchase.purchaseId,
        materialId: purchase.material,
        refundAmount: purchase.refund.amount,
        reason: reason
      });

      res.json({
        success: true,
        message: 'Refund processed successfully',
        data: {
          purchase: {
            id: purchase._id,
            purchaseId: purchase.purchaseId,
            status: purchase.status,
            refund: purchase.refund
          }
        }
      });

    } catch (error) {
      logger.errorWithContext(error, { 
        action: 'refund_processing', 
        userId: req.user._id, 
        purchaseId: req.params.id 
      });
      res.status(500).json({ 
        error: 'Failed to process refund' 
      });
    }
  }
);

/**
 * @route   GET /api/purchases/stats/summary
 * @desc    Get purchase statistics
 * @access  Private (Admin or User)
 */
router.get('/stats/summary', authenticate, async (req, res) => {
  try {
    let stats;
    
    if (['admin1', 'admin2', 'admin3'].includes(req.user.role)) {
      // Admin can see all stats
      stats = await Purchase.getPurchaseStats();
    } else {
      // Users can see their own stats (as buyer)
      stats = await Purchase.getPurchaseStats(req.user._id, 'buyer');
    }

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'purchase_stats', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch purchase statistics' 
    });
  }
});

/**
 * @route   GET /api/purchases/sales/stats
 * @desc    Get sales statistics (for creators)
 * @access  Private (Authenticated users)
 */
router.get('/sales/stats', authenticate, async (req, res) => {
  try {
    const stats = await Purchase.getPurchaseStats(req.user._id, 'seller');

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'sales_stats', 
      userId: req.user._id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch sales statistics' 
    });
  }
});

/**
 * @route   GET /api/purchases
 * @desc    Get all purchases with filters (Admin only)
 * @access  Private (Admin only)
 */
router.get('/',
  adminAuth(['admin1', 'admin2', 'admin3']),
  logAdminAction('purchases_list_viewed', 'Admin viewed purchases list'),
  async (req, res) => {
    try {
      const { 
        page = 1, 
        limit = 50, 
        status, 
        buyer, 
        seller,
        material,
        dateFrom,
        dateTo,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (status) query.status = status;
      if (buyer) query.buyer = buyer;
      if (seller) query.seller = seller;
      if (material) query.material = material;
      
      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      // Execute query
      const purchases = await Purchase.find(query)
        // .populate('buyer', 'profile.name profile.email') // TODO: Replace with JOIN
        // .populate('seller', 'profile.name profile.email') // TODO: Replace with JOIN
        // .populate('material', 'title category subject') // TODO: Replace with JOIN
        .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await Purchase.countDocuments(query);

      res.json({
        success: true,
        data: {
          purchases,
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
        action: 'purchases_list', 
        adminId: req.admin.id 
      });
      res.status(500).json({ 
        error: 'Failed to fetch purchases' 
      });
    }
  }
);

module.exports = router;