const express = require('express');
const { pool } = require('../config/mysql-db');
const StudyMaterial = require('../models/StudyMaterial');
const Purchase = require('../models/Purchase');
const Booking = require('../models/Booking');
const Payout = require('../models/Payout');
const { authenticate, authorize } = require('../middleware/auth');
const { adminAuth, logAdminAction } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const {
  createOrder,
  verifyPayment,
  capturePayment,
  createCustomer,
  createRefund,
  getPaymentDetails,
  calculateCommission
} = require('../utils/razorpay');

const router = express.Router();

/**
 * @route   POST /api/payments/create-order
 * @desc    Create Razorpay order for payment
 * @access  Private (Authenticated users)
 */
router.post('/create-order', authenticate, async (req, res) => {
  try {
    const {
      amount,
      currency = 'INR',
      type, // 'material_purchase', 'booking', 'subscription'
      itemId,
      description,
      customer_id = null
    } = req.body;

    // Validate amount
    if (!amount || amount < 1) {
      return res.status(400).json({
        error: 'Invalid amount. Minimum amount is ₹1.'
      });
    }

    // Validate type and itemId
    if (!type || !itemId) {
      return res.status(400).json({
        error: 'Payment type and item ID are required.'
      });
    }

    // Verify item exists and user can purchase it
    let item;
    let itemType;

    if (type === 'material_purchase') {
      item = await StudyMaterial.findById(itemId);
      itemType = 'Study Material';
      
      if (!item || !item.isActive || item.status !== 'published') {
        return res.status(404).json({
          error: 'Material not found or not available for purchase.'
        });
      }

      // Check if user already purchased
      const existingPurchase = await Purchase.findOne({ user_id: req.user._id, material_id: itemId });
      if (existingPurchase) {
        return res.status(400).json({
          error: 'You have already purchased this material.'
        });
      }

      // Don't allow creators to buy their own materials
      if (item.creator_id && item.creator_id.toString() === req.user._id.toString()) {
        return res.status(400).json({
          error: 'You cannot purchase your own material.'
        });
      }

    } else if (type === 'booking') {
      const Booking = require('../models/Booking');
      item = await Booking.findById(itemId);
      itemType = 'Mentor Session';
      
      if (!item || item.status !== 'pending') {
        return res.status(404).json({
          error: 'Booking not found or not available for payment.'
        });
      }

      // Verify user is the buyer
      if (item.student_id && item.student_id.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          error: 'Access denied. You can only pay for your own bookings.'
        });
      }

    } else {
      return res.status(400).json({
        error: 'Invalid payment type.'
      });
    }

    // Create Razorpay order
    const orderResult = await createOrder({
      amount,
      currency,
      receipt: `${type}_${itemId}_${Date.now()}`,
      notes: {
        type,
        itemId: itemId,
        userId: req.user._id.toString(),
        itemType,
        itemName: item.title || item.bookingId
      },
      customer_id
    });

    if (!orderResult.success) {
      return res.status(500).json({
        error: 'Failed to create payment order: ' + orderResult.error
      });
    }

    logger.userAction(req.user._id, 'payment_order_created', {
      orderId: orderResult.order.id,
      amount: amount,
      type: type,
      itemId: itemId,
      itemType: itemType
    });

    res.json({
      success: true,
      message: 'Payment order created successfully',
      data: {
        order: orderResult.order,
        amount: amount,
        currency: currency,
        type: type,
        itemId: itemId,
        itemType: itemType
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'payment_order_creation', 
      userId: req.user._id 
    });
    res.status(500).json({
      error: 'Failed to create payment order'
    });
  }
});

/**
 * @route   POST /api/payments/verify
 * @desc    Verify Razorpay payment and complete transaction
 * @access  Private (Authenticated users)
 */
router.post('/verify', authenticate, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      type,
      itemId
    } = req.body;

    // Verify payment signature
    const isValidSignature = verifyPayment(
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    );

    if (!isValidSignature) {
      return res.status(400).json({
        error: 'Invalid payment signature'
      });
    }

    // Get payment details from Razorpay
    const paymentResult = await getPaymentDetails(razorpay_payment_id);
    if (!paymentResult.success) {
      return res.status(500).json({
        error: 'Failed to verify payment details'
      });
    }

    const payment = paymentResult.payment;

    // Process payment based on type
    let transactionResult;

    if (type === 'material_purchase') {
      transactionResult = await processMaterialPurchase(req.user._id, itemId, payment);
    } else if (type === 'booking') {
      transactionResult = await processBookingPayment(req.user._id, itemId, payment);
    } else {
      return res.status(400).json({
        error: 'Invalid transaction type'
      });
    }

    if (!transactionResult.success) {
      return res.status(500).json({
        error: transactionResult.error
      });
    }

    logger.userAction(req.user._id, 'payment_verified', {
      paymentId: razorpay_payment_id,
      orderId: razorpay_order_id,
      amount: payment.amount,
      type: type,
      itemId: itemId
    });

    res.json({
      success: true,
      message: 'Payment verified and transaction completed successfully',
      data: {
        payment: {
          id: razorpay_payment_id,
          amount: payment.amount,
          status: payment.status,
          method: payment.method,
          created_at: payment.created_at
        },
        transaction: transactionResult.transaction
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'payment_verification', 
      userId: req.user._id 
    });
    res.status(500).json({
      error: 'Failed to verify payment'
    });
  }
});

/**
 * @route   POST /api/payments/refund
 * @desc    Create refund for payment
 * @access  Private (Admin or User)
 */
router.post('/refund', authenticate, async (req, res) => {
  try {
    const {
      payment_id,
      amount,
      reason,
      transaction_type,
      transaction_id
    } = req.body;

    // Get transaction details
    let transaction;
    if (transaction_type === 'purchase') {
      transaction = await Purchase.findById(transaction_id);
    } else if (transaction_type === 'booking') {
      transaction = await Booking.findById(transaction_id);
    } else {
      return res.status(400).json({
        error: 'Invalid transaction type'
      });
    }

    if (!transaction) {
      return res.status(404).json({
        error: 'Transaction not found'
      });
    }

    // Check if user can refund this transaction
    const canRefund = req.user._id.toString() === transaction.buyer.toString() ||
                     req.user._id.toString() === transaction.student.toString() ||
                     ['admin1', 'admin2'].includes(req.user.role);

    if (!canRefund) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    // Check if transaction can be refunded
    if (transaction.status !== 'completed') {
      return res.status(400).json({
        error: 'Only completed transactions can be refunded'
      });
    }

    // Create Razorpay refund
    const refundResult = await createRefund(
      payment_id,
      amount || transaction.pricing.finalPrice,
      reason
    );

    if (!refundResult.success) {
      return res.status(500).json({
        error: 'Failed to create refund: ' + refundResult.error
      });
    }

    // Update transaction status for MySQL
    if (transaction_type === 'purchase') {
      // MySQL: Update purchase with refund info
      await Purchase.update(transaction.id, {
        status: 'refunded',
        razorpay_refund_id: refundResult.refund.id
      });
    } else if (transaction_type === 'booking') {
      // MySQL: Update booking with refund info
      await Booking.update(transaction.id, {
        status: 'cancelled',
        payment_status: 'refunded',
        refunded_at: new Date().toISOString()
      });
    }

    logger.userAction(req.user._id, 'refund_created', {
      paymentId: payment_id,
      refundId: refundResult.refund.id,
      amount: amount,
      reason: reason,
      transactionType: transaction_type,
      transactionId: transaction_id
    });

    res.json({
      success: true,
      message: 'Refund created successfully',
      data: {
        refund: refundResult.refund,
        transaction: {
          id: transaction._id,
          status: transaction.status
        }
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'refund_creation', 
      userId: req.user._id 
    });
    res.status(500).json({
      error: 'Failed to create refund'
    });
  }
});

/**
 * @route   GET /api/payments/transactions
 * @desc    Get user's payment transactions
 * @access  Private (Authenticated users)
 */
router.get('/transactions', authenticate, async (req, res) => {
  try {
    const { 
      type,
      status,
      page = 1, 
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    let transactions = [];
    let total = 0;

    // Get purchases
    const purchaseQuery = { buyer: req.user._id };
    if (status) purchaseQuery.status = status;

    const purchases = await Purchase.find(purchaseQuery)
      // .populate('material', 'title category subject') // TODO: Replace with JOIN
      // .populate('seller', 'profile.name') // TODO: Replace with JOIN
      .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Get bookings
    const bookingQuery = { student: req.user._id };
    if (status) bookingQuery.status = status;

    const bookings = await Booking.find(bookingQuery)
      // .populate('mentor', 'user') // TODO: Replace with JOIN
      // .populate('mentor.user', 'profile.name') // TODO: Replace with JOIN
      .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Combine and format transactions
    const allTransactions = [
      ...purchases.map(p => ({
        id: p._id,
        type: 'purchase',
        title: p.material.title,
        category: p.material.category,
        amount: p.pricing.finalPrice,
        status: p.status,
        createdAt: p.createdAt,
        completedAt: p.completedAt
      })),
      ...bookings.map(b => ({
        id: b._id,
        type: 'booking',
        title: `${b.mentor.user.profile.name} - ${b.subjects.join(', ')}`,
        category: 'Mentor Session',
        amount: b.pricing.totalAmount,
        status: b.status,
        createdAt: b.createdAt,
        completedAt: b.completedAt
      }))
    ];

    // Sort combined transactions
    allTransactions.sort((a, b) => {
      const aDate = new Date(a.createdAt);
      const bDate = new Date(b.createdAt);
      return sortOrder === 'desc' ? bDate - aDate : aDate - bDate;
    });

    // Apply pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    transactions = allTransactions.slice(startIndex, endIndex);
    total = allTransactions.length;

    res.json({
      success: true,
      data: {
        transactions,
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
      action: 'payment_transactions', 
      userId: req.user._id 
    });
    res.status(500).json({
      error: 'Failed to fetch transactions'
    });
  }
});

/**
 * @route   GET /api/payments/stats
 * @desc    Get payment statistics
 * @access  Private (Admin or User)
 */
router.get('/stats', authenticate, async (req, res) => {
  try {
    let stats;

    if (['admin1', 'admin2', 'admin3'].includes(req.user.role)) {
      // Admin can see all payment stats
      stats = await getAdminPaymentStats();
    } else {
      // Users can see their own stats
      stats = await getUserPaymentStats(req.user._id);
    }

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'payment_stats', 
      userId: req.user._id 
    });
    res.status(500).json({
      error: 'Failed to fetch payment statistics'
    });
  }
});

/**
 * @route   GET /api/payments/payouts
 * @desc    Get mentor payouts
 * @access  Private (Mentors only)
 */
router.get('/payouts', authenticate, async (req, res) => {
  try {
    // Check if user is a mentor
    const Mentor = require('../models/Mentor');
    const mentor = await Mentor.findOne({ user: req.user._id });
    
    if (!mentor) {
      return res.status(403).json({
        error: 'Access denied. Only mentors can view payouts.'
      });
    }

    const { 
      status,
      page = 1, 
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const query = { mentor: mentor._id };
    if (status) query.status = status;

    const payouts = await Payout.find(query)
      .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Payout.countDocuments(query);

    // Get payout statistics
    const payoutStats = await Payout.getPayoutStats();

    res.json({
      success: true,
      data: {
        payouts,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        },
        stats: payoutStats
      }
    });

  } catch (error) {
    logger.errorWithContext(error, { 
      action: 'payouts_list', 
      userId: req.user._id 
    });
    res.status(500).json({
      error: 'Failed to fetch payouts'
    });
  }
});

// Helper functions
async function processMaterialPurchase(userId, materialId, payment) {
  try {
    // Get material details
    const material = await StudyMaterial.findById(materialId);
    if (!material) {
      throw new Error('Material not found');
    }

    // Calculate pricing with commission
    const commissionBreakdown = calculateCommission(payment.amount / 100, 0.30);

    // Create purchase record
    const purchaseData = {
      buyer_id: userId,
      seller_id: material.creator_id,
      material_id: materialId,
      amount: payment.amount / 100,
      currency: 'INR',
      status: 'completed',
      razorpay_payment_id: payment.id,
      razorpay_order_id: payment.order_id,
      payment_method: payment.method
    };

    const purchase = await Purchase.create(purchaseData);

    // Update material stats - MySQL implementation needed
    // await material.recordPurchase(payment.amount / 100);

    return {
      success: true,
      transaction: {
        id: purchase._id,
        type: 'purchase',
        status: 'completed'
      }
    };

  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}

async function processBookingPayment(userId, bookingId, payment) {
  try {
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      throw new Error('Booking not found');
    }

    // Calculate pricing with commission
    const commissionBreakdown = calculateCommission(payment.amount / 100, 0.30);

    // Update booking payment status - use MySQL update
    const bookingUpdateData = {
      status: 'confirmed',
      payment_id: payment.id,
      razorpay_payment_id: payment.id,
      razorpay_order_id: payment.order_id
    };
    
    await Booking.update(bookingId, bookingUpdateData);

    return {
      success: true,
      transaction: {
        id: booking._id,
        type: 'booking',
        status: 'confirmed'
      }
    };

  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}

async function getAdminPaymentStats() {
  try {
    // MySQL aggregate queries - simple implementation
    const [purchaseStats] = await pool.execute(`
      SELECT status, COUNT(*) as count, SUM(amount) as totalAmount
      FROM payments
      GROUP BY status
    `);

    const [bookingStats] = await pool.execute(`
      SELECT status, COUNT(*) as count, SUM(amount) as totalAmount
      FROM bookings
      GROUP BY status
    `);

    const totalRevenue = purchaseStats.reduce((sum, stat) => sum + (stat.totalAmount * 0.30 || 0), 0) +
                         bookingStats.reduce((sum, stat) => sum + (stat.totalAmount * 0.30 || 0), 0);

    return {
      purchases: purchaseStats,
      bookings: bookingStats,
      totalRevenue
    };

  } catch (error) {
    throw error;
  }
}

async function getUserPaymentStats(userId) {
  try {
    // MySQL implementation - simple queries
    const [purchases] = await pool.execute(
      'SELECT COUNT(*) as total, SUM(amount) as totalAmount FROM payments WHERE user_id = ?',
      [userId]
    );
    const [bookings] = await pool.execute(
      'SELECT COUNT(*) as total, SUM(amount) as totalAmount FROM bookings WHERE student_id = ?',
      [userId]
    );

    return {
      purchases: purchases[0],
      bookings: bookings[0]
    };

  } catch (error) {
    throw error;
  }
}

module.exports = router;

