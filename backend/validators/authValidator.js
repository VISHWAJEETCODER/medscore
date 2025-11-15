const { body } = require("express-validator");

/**
 * Signup validation rules (Bug #20 fix - removed redundant email check)
 */
const signupValidation = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail(),

  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/[0-9]/)
    .withMessage(
      "Password must contain at least one number (optional: special character for stronger security)",
    )
    .optional({ checkFalsy: true })
    .matches(/[!@#$%^&*(),.?":{}|<>]/),

  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Password confirmation does not match password");
    }
    return true;
  }),

  body("name")
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage("Name must be between 2 and 50 characters")
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage("Name can only contain letters and spaces"),

  body("phone")
    .optional()
    .isMobilePhone("en-IN")
    .withMessage("Please provide a valid Indian mobile number"),
];

/**
 * Login validation rules
 */
const loginValidation = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail(),

  body("password").notEmpty().withMessage("Password is required"),
];

/**
 * OTP verification validation rules
 */
const otpValidation = [
  body("tempToken").notEmpty().withMessage("Temporary token is required"),

  body("otp")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be exactly 6 digits")
    .isNumeric()
    .withMessage("OTP must contain only numbers"),
];

/**
 * Password reset validation rules
 */
const passwordResetValidation = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail(),
];

/**
 * New password validation rules
 */
const newPasswordValidation = [
  body("token").notEmpty().withMessage("Reset token is required"),

  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character"),

  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Password confirmation does not match password");
    }
    return true;
  }),
];

/**
 * Profile update validation rules
 */
const profileUpdateValidation = [
  body("name")
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage("Name must be between 2 and 50 characters")
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage("Name can only contain letters and spaces"),

  body("phone")
    .optional()
    .isMobilePhone("en-IN")
    .withMessage("Please provide a valid Indian mobile number"),

  body("state")
    .optional()
    .custom((value) => {
      const indianStates = [
        "Andhra Pradesh",
        "Arunachal Pradesh",
        "Assam",
        "Bihar",
        "Chhattisgarh",
        "Goa",
        "Gujarat",
        "Haryana",
        "Himachal Pradesh",
        "Jharkhand",
        "Karnataka",
        "Kerala",
        "Madhya Pradesh",
        "Maharashtra",
        "Manipur",
        "Meghalaya",
        "Mizoram",
        "Nagaland",
        "Odisha",
        "Punjab",
        "Rajasthan",
        "Sikkim",
        "Tamil Nadu",
        "Telangana",
        "Tripura",
        "Uttar Pradesh",
        "Uttarakhand",
        "West Bengal",
        "Delhi",
        "Puducherry",
      ];
      // Bug #24 fix - Allow international or other
      if (
        value &&
        !indianStates.includes(value) &&
        value !== "Other" &&
        value !== "International"
      ) {
        throw new Error(
          "Please select a valid state or choose Other/International",
        );
      }
      return true;
    }),

  body("college")
    .optional()
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage("College name must be between 2 and 200 characters"),

  body("year")
    .optional()
    .isInt({ min: 1, max: 5 })
    .withMessage("Year must be between 1 and 5"),
];

module.exports = {
  signupValidation,
  loginValidation,
  otpValidation,
  passwordResetValidation,
  newPasswordValidation,
  profileUpdateValidation,
};
