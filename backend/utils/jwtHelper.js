// ===== JWT HELPER UTILITIES =====

const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Generate Access Token
 * @param {Object} payload - User data to encode
 * @returns {String} JWT token
 */
const generateAccessToken = (payload) => {
  return jwt.sign(
    {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
      isVerified: payload.isVerified
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE || '30d',
      issuer: 'medscore',
      audience: 'medscore-users'
    }
  );
};

/**
 * Generate Refresh Token
 * @param {Object} payload - User data to encode
 * @returns {String} JWT refresh token
 */
const generateRefreshToken = (payload) => {
  return jwt.sign(
    {
      userId: payload.userId,
      email: payload.email,
      type: 'refresh'
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRE || '90d',
      issuer: 'medscore',
      audience: 'medscore-users'
    }
  );
};

/**
 * Generate Token Pair (Access + Refresh)
 * @param {Object} user - User object
 * @returns {Object} Token pair
 */
const generateTokenPair = (user) => {
  const payload = {
    userId: user.id,
    email: user.email,
    role: user.role,
    isVerified: user.isVerified
  };

  return {
    accessToken: generateAccessToken(payload),
    refreshToken: generateRefreshToken(payload),
    expiresIn: process.env.JWT_EXPIRE || '30d'
  };
};

/**
 * Verify Access Token
 * @param {String} token - JWT token
 * @returns {Object} Decoded token payload
 */
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'medscore',
      audience: 'medscore-users'
    });
  } catch (error) {
    throw new Error('Invalid or expired access token');
  }
};

/**
 * Verify Refresh Token
 * @param {String} token - JWT refresh token
 * @returns {Object} Decoded token payload
 */
const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
      issuer: 'medscore',
      audience: 'medscore-users'
    });

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

/**
 * Decode Token (without verification - for debugging)
 * @param {String} token - JWT token
 * @returns {Object} Decoded token payload
 */
const decodeToken = (token) => {
  return jwt.decode(token);
};

/**
 * Check if token is expired
 * @param {String} token - JWT token
 * @returns {Boolean} True if expired
 */
const isTokenExpired = (token) => {
  try {
    const decoded = decodeToken(token);
    if (!decoded || !decoded.exp) return true;
    
    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  } catch (error) {
    return true;
  }
};

/**
 * Get token expiry time
 * @param {String} token - JWT token
 * @returns {Date|null} Expiry date or null
 */
const getTokenExpiry = (token) => {
  try {
    const decoded = decodeToken(token);
    if (!decoded || !decoded.exp) return null;
    
    return new Date(decoded.exp * 1000);
  } catch (error) {
    return null;
  }
};

/**
 * Generate password reset token
 * @param {Object} user - User object
 * @returns {String} Reset token
 */
const generatePasswordResetToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      type: 'password-reset',
      timestamp: Date.now()
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '1h', // Short expiry for security
      issuer: 'medscore',
      audience: 'medscore-users'
    }
  );
};

/**
 * Verify password reset token
 * @param {String} token - Reset token
 * @returns {Object} Decoded token payload
 */
const verifyPasswordResetToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'medscore',
      audience: 'medscore-users'
    });

    if (decoded.type !== 'password-reset') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired reset token');
  }
};

/**
 * Generate email verification token
 * @param {Object} user - User object
 * @returns {String} Verification token
 */
const generateEmailVerificationToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      type: 'email-verification'
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '24h',
      issuer: 'medscore',
      audience: 'medscore-users'
    }
  );
};

/**
 * Verify email verification token
 * @param {String} token - Verification token
 * @returns {Object} Decoded token payload
 */
const verifyEmailVerificationToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'medscore',
      audience: 'medscore-users'
    });

    if (decoded.type !== 'email-verification') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired verification token');
  }
};

/**
 * Extract token from Authorization header
 * @param {String} authHeader - Authorization header value
 * @returns {String|null} Token or null
 */
const extractTokenFromHeader = (authHeader) => {
  if (!authHeader) return null;
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }
  
  return parts[1];
};

/**
 * Generate API key for admin access
 * @param {Object} user - User object
 * @returns {String} API key
 */
const generateApiKey = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      type: 'api-key',
      permissions: getUserPermissions(user.role)
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '1y', // Long expiry for API keys
      issuer: 'medscore',
      audience: 'medscore-api'
    }
  );
};

/**
 * Get user permissions based on role
 * @param {String} role - User role
 * @returns {Array} Permissions array
 */
const getUserPermissions = (role) => {
  const permissions = {
    student: ['read:profile', 'update:profile', 'read:colleges', 'create:bookings', 'create:purchases'],
    mentor: ['read:profile', 'update:profile', 'read:colleges', 'create:bookings', 'create:purchases', 'create:materials', 'read:earnings'],
    admin1: ['*'], // All permissions
    admin2: ['read:*', 'create:*', 'update:*', 'delete:users', 'delete:colleges', 'delete:materials'],
    admin3: ['read:*', 'update:users', 'update:colleges', 'update:materials', 'suspend:users']
  };

  return permissions[role] || permissions.student;
};

/**
 * Check if user has specific permission
 * @param {String} role - User role
 * @param {String} permission - Required permission
 * @returns {Boolean} True if has permission
 */
const hasPermission = (role, permission) => {
  const userPermissions = getUserPermissions(role);
  
  if (userPermissions.includes('*')) return true;
  
  return userPermissions.includes(permission);
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  decodeToken,
  isTokenExpired,
  getTokenExpiry,
  generatePasswordResetToken,
  verifyPasswordResetToken,
  generateEmailVerificationToken,
  verifyEmailVerificationToken,
  extractTokenFromHeader,
  generateApiKey,
  getUserPermissions,
  hasPermission
};