const Razorpay = require('razorpay');
const crypto = require('crypto');
require('dotenv').config();

// Initialize Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

/**
 * Create Razorpay order
 * @param {Object} orderData - Order details
 * @returns {Promise<Object>} Razorpay order
 */
const createOrder = async (orderData) => {
  try {
    const {
      amount,
      currency = 'INR',
      receipt,
      notes = {},
      customer_id = null
    } = orderData;

    // Validate amount (minimum ₹1)
    if (amount < 100) { // Razorpay minimum amount is ₹1 (100 paise)
      throw new Error('Minimum amount is ₹1');
    }

    const options = {
      amount: Math.round(amount * 100), // Convert to paise
      currency,
      receipt: receipt || `receipt_${Date.now()}`,
      notes: {
        ...notes,
        created_at: new Date().toISOString()
      }
    };

    // Add customer ID if provided
    if (customer_id) {
      options.customer_id = customer_id;
    }

    const order = await razorpay.orders.create(options);

    return {
      success: true,
      order: {
        id: order.id,
        amount: order.amount,
        currency: order.currency,
        receipt: order.receipt,
        status: order.status,
        created_at: order.created_at
      }
    };

  } catch (error) {
    console.error('Razorpay order creation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Verify Razorpay payment
 * @param {String} razorpay_order_id - Razorpay order ID
 * @param {String} razorpay_payment_id - Razorpay payment ID
 * @param {String} razorpay_signature - Razorpay signature
 * @returns {Boolean} Payment verification result
 */
const verifyPayment = (razorpay_order_id, razorpay_payment_id, razorpay_signature) => {
  try {
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');

    return expectedSignature === razorpay_signature;
  } catch (error) {
    console.error('Payment verification error:', error);
    return false;
  }
};

/**
 * Capture payment
 * @param {String} payment_id - Razorpay payment ID
 * @param {Number} amount - Amount to capture (in rupees)
 * @returns {Promise<Object>} Capture result
 */
const capturePayment = async (payment_id, amount) => {
  try {
    const captureData = {
      amount: Math.round(amount * 100), // Convert to paise
      currency: 'INR'
    };

    const capture = await razorpay.payments.capture(payment_id, captureData.amount, captureData.currency);

    return {
      success: true,
      capture: {
        id: capture.id,
        amount: capture.amount,
        currency: capture.currency,
        status: capture.status,
        captured_at: capture.captured_at
      }
    };

  } catch (error) {
    console.error('Payment capture error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Create Razorpay customer
 * @param {Object} customerData - Customer details
 * @returns {Promise<Object>} Customer creation result
 */
const createCustomer = async (customerData) => {
  try {
    const {
      name,
      email,
      contact,
      notes = {}
    } = customerData;

    const customer = await razorpay.customers.create({
      name,
      email,
      contact,
      notes: {
        ...notes,
        created_at: new Date().toISOString()
      }
    });

    return {
      success: true,
      customer: {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        contact: customer.contact,
        created_at: customer.created_at
      }
    };

  } catch (error) {
    console.error('Customer creation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Create Razorpay refund
 * @param {String} payment_id - Razorpay payment ID
 * @param {Number} amount - Refund amount (in rupees)
 * @param {String} notes - Refund notes
 * @returns {Promise<Object>} Refund result
 */
const createRefund = async (payment_id, amount, notes = '') => {
  try {
    const refundData = {
      amount: Math.round(amount * 100), // Convert to paise
      notes: {
        reason: notes,
        refunded_at: new Date().toISOString()
      }
    };

    const refund = await razorpay.payments.refund(payment_id, refundData);

    return {
      success: true,
      refund: {
        id: refund.id,
        amount: refund.amount,
        currency: refund.currency,
        status: refund.status,
        notes: refund.notes,
        created_at: refund.created_at
      }
    };

  } catch (error) {
    console.error('Refund creation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Get payment details
 * @param {String} payment_id - Razorpay payment ID
 * @returns {Promise<Object>} Payment details
 */
const getPaymentDetails = async (payment_id) => {
  try {
    const payment = await razorpay.payments.fetch(payment_id);

    return {
      success: true,
      payment: {
        id: payment.id,
        amount: payment.amount,
        currency: payment.currency,
        status: payment.status,
        method: payment.method,
        description: payment.description,
        created_at: payment.created_at,
        captured_at: payment.captured_at
      }
    };

  } catch (error) {
    console.error('Payment fetch error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Get order details
 * @param {String} order_id - Razorpay order ID
 * @returns {Promise<Object>} Order details
 */
const getOrderDetails = async (order_id) => {
  try {
    const order = await razorpay.orders.fetch(order_id);

    return {
      success: true,
      order: {
        id: order.id,
        amount: order.amount,
        currency: order.currency,
        receipt: order.receipt,
        status: order.status,
        created_at: order.created_at,
        notes: order.notes
      }
    };

  } catch (error) {
    console.error('Order fetch error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Create Razorpay invoice (for recurring payments)
 * @param {Object} invoiceData - Invoice details
 * @returns {Promise<Object>} Invoice creation result
 */
const createInvoice = async (invoiceData) => {
  try {
    const {
      type = 'invoice',
      description,
      customer_id,
      line_items,
      due_date,
      notes = {}
    } = invoiceData;

    const invoice = await razorpay.invoices.create({
      type,
      description,
      customer_id,
      line_items,
      due_date: Math.floor(due_date.getTime() / 1000), // Convert to Unix timestamp
      notes: {
        ...notes,
        created_at: new Date().toISOString()
      }
    });

    return {
      success: true,
      invoice: {
        id: invoice.id,
        status: invoice.status,
        amount: invoice.amount,
        currency: invoice.currency,
        description: invoice.description,
        due_date: invoice.due_date,
        created_at: invoice.created_at
      }
    };

  } catch (error) {
    console.error('Invoice creation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Generate Razorpay payment link
 * @param {Object} linkData - Payment link details
 * @returns {Promise<Object>} Payment link result
 */
const createPaymentLink = async (linkData) => {
  try {
    const {
      amount,
      currency = 'INR',
      description,
      customer,
      notify = { sms: true, email: true },
      reminder_enable = true,
      callback_url,
      callback_method = 'get'
    } = linkData;

    const paymentLink = await razorpay.paymentLink.create({
      amount: Math.round(amount * 100), // Convert to paise
      currency,
      description,
      customer,
      notify,
      reminder_enable,
      callback_url,
      callback_method
    });

    return {
      success: true,
      paymentLink: {
        id: paymentLink.id,
        short_url: paymentLink.short_url,
        amount: paymentLink.amount,
        currency: paymentLink.currency,
        status: paymentLink.status,
        created_at: paymentLink.created_at
      }
    };

  } catch (error) {
    console.error('Payment link creation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Calculate commission split
 * @param {Number} totalAmount - Total amount
 * @param {Number} platformCommission - Platform commission percentage (default 30%)
 * @returns {Object} Commission breakdown
 */
const calculateCommission = (totalAmount, platformCommission = 0.30) => {
  const platformEarnings = Math.round(totalAmount * platformCommission);
  const creatorEarnings = totalAmount - platformEarnings;

  return {
    totalAmount,
    platformEarnings,
    creatorEarnings,
    platformCommission: platformCommission * 100,
    creatorCommission: (1 - platformCommission) * 100
  };
};

module.exports = {
  razorpay,
  createOrder,
  verifyPayment,
  capturePayment,
  createCustomer,
  createRefund,
  getPaymentDetails,
  getOrderDetails,
  createInvoice,
  createPaymentLink,
  calculateCommission
};

