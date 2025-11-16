const express = require("express");
const { body } = require("express-validator");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const OTP = require("../models/OTP");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/jwtHelper");
const {
  generateOTP,
  sendOTP,
  storeOTP,
  verifyOTP,
} = require("../utils/otpService");
const { authenticate, authorize } = require("../middleware/auth");
const {
  signupValidation,
  loginValidation,
  otpValidation,
  profileUpdateValidation,
} = require("../validators/authValidator");
const {
  loginLimiter,
  signupLimiter,
  otpLimiter,
} = require("../middleware/rateLimiter");
const { processReferral, validateReferralCode } = require("../utils/referral");
const { uploadSingle, handleUploadError } = require("../middleware/upload");
const { localStorageUtils } = require("../utils/localStorage");
const { avatarUtils } = require("../utils/defaultAvatars");

// Helper function to generate unique referral code
const generateReferralCode = () => {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return code;
};
const passport = require("../config/googleAuth");

const router = express.Router();

/**
 * @route   POST /api/auth/check-email
 * @desc    Check if email already exists
 * @access  Public
 */
router.post("/check-email", otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        error: "Email is required",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });

    res.json({
      exists: !!existingUser,
    });
  } catch (error) {
    console.error("Check email error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/send-signup-otp
 * @desc    Send OTP for signup verification
 * @access  Public
 */
router.post("/send-signup-otp", otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: "User with this email already exists. Please login instead.",
      });
    }

    // Generate and send OTP
    const otp = await generateOTP();
    console.log(`Generated OTP for ${email}: ${otp}`); // For debugging

    const sendResult = await sendOTP(email, otp, "signup");

    // Check if email was sent successfully (Bug #28 fix - better error handling)
    if (!sendResult.success) {
      console.error("Failed to send OTP:", sendResult.message);
      return res.status(500).json({
        success: false,
        error:
          sendResult.message ||
          "Failed to send OTP. Please check your email and try again.",
        details:
          "Email service error. Please contact support if this persists.",
      });
    }

    // Store OTP with email as identifier for pre-signup verification
    const tempToken = email; // Use email directly as temp token for pre-signup
    const storeResult = await storeOTP(email, otp, "signup");

    // Check if OTP was stored successfully
    if (!storeResult.success) {
      console.error("Failed to store OTP:", storeResult.message);
      return res.status(500).json({
        success: false,
        error: storeResult.message || "Failed to store OTP. Please try again.",
      });
    }

    console.log(`OTP sent and stored successfully for ${email}`);

    res.json({
      success: true,
      message: "OTP sent successfully. Please check your email.",
      tempToken: tempToken,
      email: email,
    });
  } catch (error) {
    console.error("Send signup OTP error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/send-login-otp
 * @desc    Send OTP for login verification
 * @access  Public
 */
router.post("/send-login-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "No account found with this email address",
      });
    }

    // Generate and send OTP
    const otp = await generateOTP();
    const sendResult = await sendOTP(email, otp, "login");

    // Check if email was sent successfully (Bug #28 fix - better error handling)
    if (!sendResult.success) {
      console.error("Failed to send login OTP:", sendResult.message);
      return res.status(500).json({
        success: false,
        error: sendResult.message || "Failed to send OTP. Please try again.",
        details:
          "Email service error. Please verify your email address or contact support.",
      });
    }

    // Store OTP with user email
    const storeResult = await storeOTP(email, otp, "login");

    // Check if OTP was stored successfully
    if (!storeResult.success) {
      return res.status(500).json({
        success: false,
        error: storeResult.message || "Failed to store OTP. Please try again.",
      });
    }

    res.json({
      success: true,
      message: "OTP sent successfully to " + email,
      email: email,
    });
  } catch (error) {
    console.error("Send login OTP error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/verify-otp-only
 * @desc    Verify OTP without creating user (email verification only)
 * @access  Public
 */
router.post("/verify-otp-only", async (req, res) => {
  try {
    const { email, otp, type } = req.body;

    // Validate required fields
    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        error: "Email and OTP are required",
      });
    }

    // Verify OTP
    const otpResult = await verifyOTP(email, otp, type || "signup");

    if (!otpResult.valid) {
      return res.status(401).json({
        success: false,
        error: otpResult.message || "Invalid or expired OTP",
      });
    }

    // OTP verified successfully - just return success
    // User will complete profile in next step
    return res.status(200).json({
      success: true,
      message: "Email verified successfully. Please complete your profile.",
      email: email,
    });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to verify OTP",
    });
  }
});

/**
 * @route   POST /api/auth/complete-signup
 * @desc    Complete signup after OTP verification (create user account)
 * @access  Public
 */
router.post("/complete-signup", async (req, res) => {
  try {
    const {
      email,
      password,
      name,
      phone,
      state,
      college,
      year,
      role,
      referralCode,
    } = req.body;

    console.log("📝 Complete signup request received:");
    console.log("Email:", email);
    console.log("Name:", name);
    console.log("Phone:", phone);
    console.log("Role:", role);
    console.log("College:", college);
    console.log("Year:", year);

    // Validate required fields
    if (!email || !password || !name) {
      console.error("❌ Missing required fields");
      return res.status(400).json({
        success: false,
        error: "Email, password, and name are required",
      });
    }

    // Check if user already exists
    console.log("🔍 Checking if user exists:", email);
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.error("❌ User already exists:", email);
      return res.status(400).json({
        success: false,
        error: "User with this email already exists",
      });
    }
    console.log("✅ User does not exist, proceeding with creation");

    // Validate referral code if provided
    let referralValidation = null;
    if (referralCode) {
      referralValidation = await validateReferralCode(referralCode);
      if (!referralValidation.success) {
        return res.status(400).json({
          success: false,
          error: referralValidation.error,
        });
      }
    }

    // Create new user
    console.log("👤 Creating new user object...");

    // Prepare user data - college and year are optional for students
    const userData = {
      email,
      password,
      name,
      phone: phone || null,
      state: state || null,
      role: role || "student",
      is_verified: true, // Email already verified via OTP
      referral_code: generateReferralCode(),
      referred_by: referralCode || null,
    };

    // Add college and year only if provided (required for mentors, optional for students)
    if (college) userData.college = college;
    if (year) userData.year = year;

    const user = new User(userData);

    console.log("💾 Saving user to database...");
    const savedUser = await user.save();
    console.log("✅ User saved successfully:", savedUser._id);

    // Update referrer's stats if referral code was used
    if (referralValidation && referralValidation.referrer) {
      await User.findByIdAndUpdate(referralValidation.referrer._id, {
        $inc: { total_referrals: 1 },
      });
    }

    // Generate JWT token
    console.log("🔐 Generating JWT token...");
    const accessToken = jwt.sign(
      { id: savedUser._id, email: savedUser.email, role: savedUser.role },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "7d" },
    );

    console.log("✅ Complete signup successful for:", email);
    return res.status(201).json({
      success: true,
      message: "Account created successfully",
      accessToken,
      user: {
        id: savedUser._id,
        name: savedUser.name,
        email: savedUser.email,
        role: savedUser.role,
        referral_code: savedUser.referral_code,
      },
    });
  } catch (error) {
    console.error("❌ Error completing signup:", error);
    console.error("Error name:", error.name);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);
    console.error("Full error:", JSON.stringify(error, null, 2));

    // Handle specific error types
    if (error.code === 11000) {
      // Duplicate key error (email already exists)
      console.error("❌ Duplicate key error (11000)");
      return res.status(400).json({
        success: false,
        error: "An account with this email already exists",
      });
    }

    if (error.name === "ValidationError") {
      // Mongoose validation error
      console.error("❌ Mongoose validation error");
      const messages = Object.values(error.errors).map((err) => err.message);
      console.error("Validation messages:", messages);
      return res.status(400).json({
        success: false,
        error: messages.join(", "),
      });
    }

    // Generic error
    console.error("❌ Generic error occurred");
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to create account. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/verify-signup-otp
 * @desc    Verify OTP and create account (legacy route - kept for backward compatibility)
 * @access  Public
 */
router.post("/verify-signup-otp", async (req, res) => {
  try {
    const {
      email,
      otp,
      password,
      name,
      phone,
      state,
      college,
      year,
      referralCode,
    } = req.body;

    // Validate required fields
    if (!email || !otp || !password || !name) {
      return res.status(400).json({
        success: false,
        error: "Email, OTP, password, and name are required",
      });
    }

    // Verify OTP
    const otpResult = await verifyOTP(email, otp, "signup");
    if (!otpResult.valid) {
      return res.status(401).json({
        success: false,
        error: otpResult.message || "Invalid or expired OTP",
      });
    }

    // Check if user already exists (double check)
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: "User with this email already exists",
      });
    }

    // Validate referral code if provided
    let referralValidation = null;
    if (referralCode) {
      referralValidation = await validateReferralCode(referralCode);
      if (!referralValidation.success) {
        return res.status(400).json({
          success: false,
          error: referralValidation.error,
        });
      }
    }

    // Create new user (Bug #47, #48, #57 fix - add error handling)
    let savedUser;
    try {
      const user = new User({
        email,
        password,
        name,
        phone,
        state,
        college,
        year,
        role: "student",
        isVerified: true,
      });

      savedUser = await user.save();
    } catch (dbError) {
      console.error("Database error during user creation:", dbError);
      return res.status(500).json({
        success: false,
        error: "Database error. Please try again later.",
        code: "DB_CREATE_USER_ERROR",
      });
    }

    // Process referral if code was provided and valid (Bug #22, #46 fix - transaction safety)
    let referralResult = null;
    if (referralCode && referralValidation && referralValidation.success) {
      try {
        referralResult = await processReferral(referralCode, savedUser.id);
      } catch (referralError) {
        console.error("Referral processing error:", referralError);
        // Continue without referral - user is already created
        console.warn("User created but referral processing failed");
      }
    }

    // Generate JWT tokens
    const accessToken = generateAccessToken({
      userId: savedUser.id,
      email: savedUser.email,
      role: savedUser.role,
    });

    const refreshToken = generateRefreshToken({
      userId: savedUser.id,
      email: savedUser.email,
    });

    res.status(201).json({
      success: true,
      message: "Account created successfully!",
      accessToken,
      refreshToken,
      user: {
        id: savedUser.id,
        name: savedUser.name,
        email: savedUser.email,
        role: savedUser.role,
        isVerified: true,
      },
      referral: referralResult?.success
        ? {
            referrerName: referralResult.referrerName,
            rewards: referralResult.rewards,
          }
        : null,
    });
  } catch (error) {
    console.error("Verify signup OTP error:", error);

    if (error.code === 11000 || error.message.includes("duplicate")) {
      return res.status(400).json({
        success: false,
        error: "User with this email already exists",
      });
    }

    res.status(500).json({
      success: false,
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user (legacy route - redirects to OTP flow)
 * @access  Public
 */
router.post("/signup", signupLimiter, async (req, res) => {
  res.status(400).json({
    error:
      "Please use the OTP verification flow. Send OTP first, then verify with user details.",
  });
});

/**
 * @route   POST /api/auth/verify-login-otp
 * @desc    Verify OTP and login user
 * @access  Public
 */
router.post("/verify-login-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        error: "Email and OTP are required",
      });
    }

    // Find user by email (Bug #47 fix - handle database errors)
    let user;
    try {
      user = await User.findOne({ email });
    } catch (dbError) {
      console.error("Database error during user lookup:", dbError);
      return res.status(500).json({
        success: false,
        error: "Database connection error. Please try again.",
        code: "DB_LOOKUP_ERROR",
      });
    }

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Check if account is locked (Bug #45 fix)
    if (user.isAccountLocked()) {
      return res.status(403).json({
        success: false,
        error:
          "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
      });
    }

    // Verify OTP
    const otpResult = await verifyOTP(email, otp, "login");
    if (!otpResult.valid) {
      // Increment failed login attempts (Bug #44 fix)
      await user.incrementLoginAttempts();
      return res.status(401).json({
        success: false,
        error: otpResult.message || "Invalid or expired OTP",
      });
    }

    // Generate JWT tokens
    const accessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    const refreshToken = generateRefreshToken({
      userId: user.id,
      email: user.email,
    });

    // Reset failed login attempts on successful login (Bug #2 fix)
    await user.resetLoginAttempts();

    res.json({
      success: true,
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
        state: user.state,
        college: user.college,
      },
    });
  } catch (error) {
    console.error("Verify login OTP error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Login user with password (legacy - redirects to OTP flow)
 * @access  Public
 */
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("🔐 Login attempt for:", email);

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required",
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.error("❌ User not found:", email);
      return res.status(401).json({
        success: false,
        error: "Invalid email or password",
      });
    }

    // Check if account is active
    if (user.is_suspended) {
      return res.status(403).json({
        success: false,
        error: "Account is suspended",
      });
    }

    // Check if account is locked
    if (
      user.account_locked_until &&
      new Date(user.account_locked_until) > new Date()
    ) {
      return res.status(403).json({
        success: false,
        error: "Account is temporarily locked. Please try again later.",
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      console.error("❌ Invalid password for:", email);

      // Increment failed login attempts
      user.failed_login_attempts = (user.failed_login_attempts || 0) + 1;

      // Lock account after 5 failed attempts
      if (user.failed_login_attempts >= 5) {
        user.account_locked_until = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        await user.save();
        return res.status(403).json({
          success: false,
          error: "Too many failed attempts. Account locked for 30 minutes.",
        });
      }

      await user.save();
      return res.status(401).json({
        success: false,
        error: "Invalid email or password",
      });
    }

    // Reset failed login attempts on successful login
    user.failed_login_attempts = 0;
    user.account_locked_until = null;
    user.last_login = new Date();
    await user.save();

    // Generate JWT token
    const accessToken = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "7d" },
    );

    console.log("✅ Login successful for:", email);

    return res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        profile_photo: user.profile_photo,
        referral_code: user.referral_code,
      },
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    return res.status(500).json({
      success: false,
      error: "Login failed. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/verify-otp
 * @desc    Verify OTP and complete login/signup
 * @access  Public
 */
router.post("/verify-otp", otpLimiter, otpValidation, async (req, res) => {
  try {
    const { tempToken, otp, type = "login" } = req.body;

    // Verify OTP
    const otpResult = await verifyOTP(tempToken, otp, type);

    if (!otpResult.valid) {
      return res.status(401).json({
        error: otpResult.message,
      });
    }

    // For signup verification with temporary token, we don't have a user yet
    if (type === "signup" && tempToken.startsWith("temp_")) {
      // For pre-signup verification, just confirm the OTP is valid
      return res.json({
        message:
          "Email verified successfully. You can now complete registration.",
        valid: true,
      });
    }

    // Get user for login or post-signup verification (Bug #5 fix)
    let user;
    if (type === "signup" && !tempToken.match(/^\d+$/)) {
      // tempToken is email for signup flow
      user = await User.findOne({ email: tempToken });
    } else {
      // tempToken is user ID
      user = await User.findById(tempToken);
    }

    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    // For signup verification, activate the account and reset any login attempts
    if (type === "signup") {
      user.isActive = true;
      await user.resetLoginAttempts();
    }

    // Generate tokens (Bug #6 fix - add email parameter)
    const accessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });
    const refreshToken = generateRefreshToken({
      userId: user.id,
      email: user.email,
    });

    res.json({
      message: `${type === "signup" ? "Email verified and " : ""}Login successful`,
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        profile: user.profile,
        isActive: user.isActive,
      },
    });
  } catch (error) {
    console.error("OTP verification error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/resend-otp
 * @desc    Resend OTP
 * @access  Public
 */
router.post("/resend-otp", otpLimiter, async (req, res) => {
  try {
    const { tempToken, type = "login", email } = req.body;

    let user, userEmail;

    // Handle temporary tokens for pre-signup verification
    if (tempToken && tempToken.startsWith("temp_")) {
      userEmail = tempToken; // For temporary tokens, the token itself is used as email identifier
    } else if (tempToken) {
      // Regular user token
      user = await User.findById(tempToken);
      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }
      userEmail = user.email;
    } else if (email) {
      // Direct email provided
      userEmail = email;
    } else {
      return res.status(400).json({
        error: "Temporary token or email is required",
      });
    }

    // Generate and send new OTP
    const otp = await generateOTP();
    await sendOTP(userEmail, otp, type);

    // Store OTP with appropriate identifier
    const otpIdentifier = user ? user.id : userEmail;
    await storeOTP(otpIdentifier, otp, type);

    res.json({
      message: "OTP resent successfully",
    });
  } catch (error) {
    console.error("Resend OTP error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get("/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    res.json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        profile: user.profile,
        isActive: user.isActive,
      },
    });
  } catch (error) {
    console.error("Get user profile error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put(
  "/profile",
  authenticate,
  profileUpdateValidation,
  async (req, res) => {
    try {
      const { name, phone, college, year, state } = req.body;

      // Find user (Bug #47 fix - handle database errors)
      let user;
      try {
        user = await User.findById(req.user.userId);
      } catch (dbError) {
        console.error("Database error during profile update:", dbError);
        return res.status(500).json({
          error: "Database connection error. Please try again.",
          code: "DB_UPDATE_ERROR",
        });
      }

      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      // Update profile fields
      if (name) user.name = name;
      if (phone) user.phone = phone;
      if (college) user.college = college;
      if (year) user.year = year;
      if (state) user.state = state;

      await user.save();

      res.json({
        message: "Profile updated successfully",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          name: user.name,
          phone: user.phone,
          college: user.college,
          year: user.year,
          state: user.state,
        },
      });
    } catch (error) {
      console.error("Update profile error:", error);
      res.status(500).json({
        error: "Internal server error. Please try again.",
      });
    }
  },
);

/**
 * @route   POST /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post("/change-password", authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Find user (Bug #47 fix - handle database errors)
    let user;
    try {
      user = await User.findById(req.user.userId);
    } catch (dbError) {
      console.error("Database error during password change:", dbError);
      return res.status(500).json({
        error: "Database connection error. Please try again.",
        code: "DB_PASSWORD_ERROR",
      });
    }

    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    // Verify current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({
        error: "Current password is incorrect",
      });
    }

    // Hash and set new password
    user.password = await User.hashPassword(newPassword);
    await user.save();

    res.json({
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Send password reset OTP
 * @access  Public
 */
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    // Find user (Bug #47 fix - handle database errors)
    let user;
    try {
      user = await User.findOne({ email });
    } catch (dbError) {
      console.error("Database error during forgot password:", dbError);
      return res.status(500).json({
        error: "Database connection error. Please try again.",
        code: "DB_FORGOT_PASSWORD_ERROR",
      });
    }

    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    // Generate and send OTP
    const otp = await generateOTP();
    await sendOTP(email, otp, "reset");
    await storeOTP(user.id, otp, "reset");

    res.json({
      message: "Password reset OTP sent to your email",
      resetToken: user.id, // Bug #10 fix - consistent naming (was email)
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with OTP
 * @access  Public
 */
router.post("/reset-password", otpValidation, async (req, res) => {
  try {
    const { resetToken, tempToken, otp, newPassword } = req.body; // Bug #10 fix - accept both names

    // Use resetToken if provided, otherwise fall back to tempToken for backward compatibility
    const identifier = resetToken || tempToken;

    // Verify OTP
    const otpResult = await verifyOTP(identifier, otp, "reset");
    if (!otpResult.valid) {
      return res.status(401).json({
        error: otpResult.message,
      });
    }

    // Get user
    const user = await User.findById(identifier);
    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    // Hash and set new password
    user.password = await User.hashPassword(newPassword);
    await user.save();

    res.json({
      message: "Password reset successfully",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (invalidate refresh token)
 * @access  Private
 */
router.post("/logout", authenticate, async (req, res) => {
  try {
    // In a real implementation, you would invalidate the refresh token
    // For now, we'll just send a success response
    res.json({
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh access token (Bug #17 fix - implemented)
 * @access  Public
 */
router.post("/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: "Refresh token is required",
      });
    }

    // Verify refresh token
    const { verifyRefreshToken } = require("../utils/jwtHelper");
    let decoded;

    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (error) {
      return res.status(401).json({
        error: "Invalid or expired refresh token",
      });
    }

    // Get user from database (Bug #47 fix - handle database errors)
    let user;
    try {
      user = await User.findById(decoded.userId);
    } catch (dbError) {
      console.error("Database error during token refresh:", dbError);
      return res.status(500).json({
        error: "Database connection error. Please try again.",
        code: "DB_REFRESH_TOKEN_ERROR",
      });
    }

    if (!user) {
      return res.status(401).json({
        error: "User not found",
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({
        error: "Account is deactivated",
      });
    }

    // Check if account is locked or suspended
    if (user.isAccountLocked() || user.isAccountSuspended()) {
      return res.status(403).json({
        error: "Account is temporarily locked or suspended",
      });
    }

    // Generate new access token
    const newAccessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    // Optionally generate new refresh token for rotation
    const newRefreshToken = generateRefreshToken({
      userId: user.id,
      email: user.email,
    });

    res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      message: "Token refreshed successfully",
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({
      error: "Internal server error. Please try again.",
    });
  }
});

/**
 * @route   GET /api/auth/google
 * @desc    Initiate Google OAuth authentication
 * @access  Public
 */
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);

/**
 * @route   GET /api/auth/google/callback
 * @desc    Handle Google OAuth callback
 * @access  Public
 */
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req, res) => {
    try {
      // Successful authentication
      const user = req.user;

      // Generate tokens
      const accessToken = generateAccessToken({
        userId: user.id,
        role: user.role,
      });
      const refreshToken = generateRefreshToken({ userId: user.id });

      // Redirect to frontend with tokens (Bug #7 fix - use environment variable)
      const frontendUrl =
        process.env.FRONTEND_URL || "https://www.medscore.xyz";
      res.redirect(
        `${frontendUrl}/login?accessToken=${accessToken}&refreshToken=${refreshToken}&userId=${user.id}`,
      );
    } catch (error) {
      console.error("Google OAuth callback error:", error);
      const frontendUrl =
        process.env.FRONTEND_URL || "https://www.medscore.xyz";
      res.redirect(`${frontendUrl}/login?error=authentication_failed`);
    }
  },
);

module.exports = router;
