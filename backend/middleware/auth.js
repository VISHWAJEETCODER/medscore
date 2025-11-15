const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { verifyAccessToken } = require("../utils/jwtHelper");
const { isBlacklisted } = require("../utils/tokenBlacklist");
const { verifyTokenInDB } = require("../utils/tokenStorage");

/**
 * Authentication middleware to verify JWT token
 */
const authenticate = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Access denied. No token provided.",
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Block blacklisted tokens (server-side logout)
    if (await isBlacklisted(token)) {
      return res.status(401).json({
        error: "Access denied. Token has been invalidated.",
      });
    }

    // Verify token exists in MySQL database
    const tokenVerification = await verifyTokenInDB(token, "access");
    if (!tokenVerification.valid) {
      return res.status(401).json({
        error: "Access denied. Token not found in database.",
      });
    }

    // Verify JWT token signature
    const decoded = verifyAccessToken(token);

    // Get user from database (use id from decoded or tokenVerification)
    const userId = decoded.id || decoded.userId || tokenVerification.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(401).json({
        error: "Invalid token. User not found.",
      });
    }

    // Remove password field manually (Bug #4 fix)
    if (user.password) {
      delete user.password;
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({
        error: "Account is deactivated.",
      });
    }

    // Check if account is locked (Bug #45 fix)
    if (user.isAccountLocked()) {
      return res.status(403).json({
        error:
          "Account is temporarily locked due to multiple failed login attempts.",
      });
    }

    // Check if user is suspended
    if (user.isAccountSuspended()) {
      return res.status(403).json({
        error: "Account is temporarily suspended.",
      });
    }

    // Add user to request object
    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(401).json({
      error: "Invalid or expired token.",
    });
  }
};

/**
 * Role-based authorization middleware
 */
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required.",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Access denied. Insufficient permissions.",
      });
    }

    next();
  };
};

/**
 * Admin hierarchy check
 * Only Grade 1 can manage Grade 2 & 3 admins
 */
const adminHierarchy = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      error: "Authentication required.",
    });
  }

  const { role } = req.user;
  const targetRole = req.body.role || req.params.role;

  // Only Grade 1 admin can add/remove Grade 2 & 3 admins
  if (role === "admin1") {
    // Grade 1 can manage anyone
    return next();
  } else if (role === "admin2") {
    // Grade 2 can manage students and mentors only
    if (["student", "mentor"].includes(targetRole)) {
      return next();
    } else {
      return res.status(403).json({
        error: "Access denied. You can only manage students and mentors.",
      });
    }
  } else if (role === "admin3") {
    // Grade 3 can only view and report, no management
    return res.status(403).json({
      error: "Access denied. You can only view and report users.",
    });
  }

  next();
};

/**
 * Optional authentication (for public endpoints that can benefit from user context)
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      // No token provided, continue without user
      return next();
    }

    const token = authHeader.substring(7);
    
    // Verify token in DB (optional check for optionalAuth)
    const tokenVerification = await verifyTokenInDB(token, "access");
    
    if (tokenVerification.valid) {
      const decoded = verifyAccessToken(token);
      const userId = decoded.id || decoded.userId || tokenVerification.userId;
      const user = await User.findById(userId);

      if (user) {
        // Remove password field manually
        delete user.password;

        if (
          user.isActive &&
          !user.isAccountSuspended() &&
          !user.isAccountLocked()
        ) {
          req.user = user;
        }
      }
    }

    next();
  } catch (error) {
    // Invalid token, continue without user
    next();
  }
};

module.exports = {
  authenticate,
  authorize,
  adminHierarchy,
  optionalAuth,
};