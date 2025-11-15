const nodemailer = require("nodemailer");
const { pool } = require("../config/mysql-db");
const brevo = require("@getbrevo/brevo");

// Make sure environment variables are loaded
if (!process.env.EMAIL_SERVICE) {
  require("dotenv").config();
}

/**
 * Generate 6-digit OTP
 */
// Generate unique 6-digit OTP (Bug #29 fix)
const generateOTP = async () => {
  let otp;
  let attempts = 0;
  const maxAttempts = 10;

  while (attempts < maxAttempts) {
    otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Check if OTP is unique in active OTPs
    try {
      const [existingOTPs] = await pool.execute(
        "SELECT id FROM otps WHERE otp = ? AND expires_at > NOW() AND is_used = FALSE",
        [otp],
      );

      if (existingOTPs.length === 0) {
        // OTP is unique
        return otp;
      }
    } catch (dbError) {
      // If database check fails, just return the OTP (fallback)
      console.warn(
        "⚠️ Could not check OTP uniqueness in database:",
        dbError.message,
      );
      return otp;
    }

    attempts++;
  }

  // If we couldn't generate unique OTP after max attempts, return anyway
  console.warn(
    "⚠️ Generated OTP after max attempts, uniqueness not guaranteed",
  );
  return otp;
};

/**
 * Send OTP via Brevo API (HTTP)
 */
const sendOTPViaBrevoAPI = async (email, otp, type = "login") => {
  try {
    const apiKey = process.env.BREVO_API_KEY || process.env.BREVO_SMTP_PASS;

    if (!apiKey) {
      throw new Error("Brevo API key not configured");
    }

    const apiInstance = new brevo.TransactionalEmailsApi();
    apiInstance.setApiKey(brevo.TransactionalEmailsApiApiKeys.apiKey, apiKey);

    const subject =
      type === "signup"
        ? "Complete Your Registration - OTP Verification"
        : (type === "forgot-password" || type === "reset")
          ? "Reset Your Password - OTP Verification"
          : "Login Verification - OTP Code";

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .otp-box { background: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; }
          .footer { margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>MedScore - OTP Verification</h2>
          <p>Your OTP code is:</p>
          <div class="otp-box">${otp}</div>
          <p>This OTP will expire in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <div class="footer">
            <p>© 2025 MedScore. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const sendSmtpEmail = {
      to: [{ email: email }],
      sender: {
        email: process.env.FROM_EMAIL || "noreply@medscore.xyz",
        name: "MedScore",
      },
      subject: subject,
      htmlContent: htmlContent,
    };

    const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log("✅ Email sent via Brevo API:", response.messageId);

    return {
      success: true,
      message: "OTP sent successfully via Brevo API",
      messageId: response.messageId,
    };
  } catch (error) {
    console.error("❌ Brevo API error:", error);
    return {
      success: false,
      message: error.message || "Failed to send email via Brevo API",
    };
  }
};

/**
 * Send OTP via email (SMTP fallback)
 */
const sendOTP = async (email, otp, type = "login") => {
  try {
    // Try Brevo API first (HTTP - no port blocking)
    if (process.env.EMAIL_SERVICE === "brevo" || !process.env.EMAIL_SERVICE) {
      console.log("📧 Attempting to send OTP via Brevo API...");
      const apiResult = await sendOTPViaBrevoAPI(email, otp, type);
      if (apiResult.success) {
        return apiResult;
      }
      console.log("⚠️ Brevo API failed, falling back to SMTP...");
    }

    // Log environment variables for debugging
    console.log("Email environment variables:", {
      EMAIL_SERVICE: process.env.EMAIL_SERVICE,
      BREVO_SMTP_HOST: process.env.BREVO_SMTP_HOST,
      BREVO_SMTP_USER: process.env.BREVO_SMTP_USER,
      BREVO_SMTP_PASS: process.env.BREVO_SMTP_PASS
        ? "***SET***"
        : "***NOT SET***",
      GMAIL_USER: process.env.GMAIL_USER,
      GMAIL_APP_PASSWORD: process.env.GMAIL_APP_PASSWORD
        ? "***SET***"
        : "***NOT SET***",
      OUTLOOK_USER: process.env.OUTLOOK_USER,
      OUTLOOK_APP_PASSWORD: process.env.OUTLOOK_APP_PASSWORD
        ? "***SET***"
        : "***NOT SET***",
    });

    // Determine email service based on environment variable (Bug #31 fix)
    const emailService = process.env.EMAIL_SERVICE || "brevo";

    let transporterConfig;
    let selectedService = emailService;

    // Respect EMAIL_SERVICE priority - check configured service FIRST
    if (
      emailService === "brevo" &&
      process.env.BREVO_SMTP_USER &&
      process.env.BREVO_SMTP_PASS
    ) {
      // Brevo as primary (if configured)
      transporterConfig = {
        host: process.env.BREVO_SMTP_HOST || "smtp-relay.brevo.com",
        port: Number(process.env.BREVO_SMTP_PORT || 587),
        secure: false,
        requireTLS: true,
        tls: {
          rejectUnauthorized: false,
        },
        connectionTimeout: 30000,
        greetingTimeout: 30000,
        socketTimeout: 30000,
        auth: {
          user: process.env.BREVO_SMTP_USER,
          pass: process.env.BREVO_SMTP_PASS,
        },
      };
      selectedService = "brevo";
    } else if (
      emailService === "gmail" &&
      process.env.GMAIL_USER &&
      process.env.GMAIL_APP_PASSWORD
    ) {
      // Gmail (if configured and selected)
      transporterConfig = {
        service: "gmail",
        auth: {
          user: process.env.GMAIL_USER,
          pass: process.env.GMAIL_APP_PASSWORD,
        },
      };
      selectedService = "gmail";
    } else if (
      emailService === "outlook" &&
      process.env.OUTLOOK_USER &&
      process.env.OUTLOOK_APP_PASSWORD
    ) {
      // Outlook (if configured and selected)
      transporterConfig = {
        service: "hotmail",
        auth: {
          user: process.env.OUTLOOK_USER,
          pass: process.env.OUTLOOK_APP_PASSWORD,
        },
      };
      selectedService = "outlook";
    } else {
      // Fallback chain: Try Brevo -> Gmail -> Outlook
      if (process.env.BREVO_SMTP_USER && process.env.BREVO_SMTP_PASS) {
        transporterConfig = {
          host: "smtp-relay.brevo.com",
          port: 587,
          secure: false,
          auth: {
            user: process.env.BREVO_SMTP_USER,
            pass: process.env.BREVO_SMTP_PASS,
          },
        };
        selectedService = "brevo";
      } else if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
        transporterConfig = {
          service: "gmail",
          auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_APP_PASSWORD,
          },
        };
        selectedService = "gmail";
      } else if (process.env.OUTLOOK_USER && process.env.OUTLOOK_APP_PASSWORD) {
        transporterConfig = {
          service: "hotmail",
          auth: {
            user: process.env.OUTLOOK_USER,
            pass: process.env.OUTLOOK_APP_PASSWORD,
          },
        };
        selectedService = "outlook";
      } else {
        throw new Error(
          "No email service configured. Please set up email credentials in .env file.",
        );
      }
    }

    console.log("Transporter config:", {
      service: selectedService,
      host: transporterConfig.host,
      port: transporterConfig.port,
      secure: transporterConfig.secure,
      authUser: transporterConfig.auth?.user ? "***SET***" : "***NOT SET***",
    });

    const transporter = nodemailer.createTransport(transporterConfig);

    const subject =
      type === "login"
        ? "Login OTP"
        : type === "signup"
          ? "Signup Verification OTP"
          : "Password Reset OTP";

    const message = `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #f0f4ff 0%, #e6f0ff 100%);">
        <div style="background: white; padding: 0; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); overflow: hidden;">

          <!-- Header with Logo -->
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px 20px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 15px;">🔐</div>
            <h1 style="color: white; font-size: 32px; margin: 0 0 10px 0; font-weight: 700; letter-spacing: 1px;">
              MedScore
            </h1>
            <p style="color: rgba(255,255,255,0.9); font-size: 18px; margin: 0; font-weight: 300;">
              ${subject}
            </p>
          </div>

          <!-- Content -->
          <div style="padding: 40px 30px;">

            <!-- Welcome Message -->
            <div style="text-align: center; margin-bottom: 30px;">
              <h2 style="color: #1e40af; font-size: 24px; margin: 0 0 15px 0; font-weight: 600;">
                Verification Code
              </h2>
              <p style="color: #64748b; font-size: 16px; margin: 0; line-height: 1.5;">
                Please use this code to verify your account
              </p>
            </div>

            <!-- OTP Box -->
            <div style="text-align: center; margin: 40px 0;">
              <div style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 8px; border-radius: 16px; box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);">
                <div style="background: white; padding: 30px 50px; border-radius: 12px;">
                  <div style="font-size: 18px; color: #64748b; margin-bottom: 15px; font-weight: 500;">
                    Your Code
                  </div>
                  <div style="font-size: 48px; font-weight: 800; color: #1e40af; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                    ${otp}
                  </div>
                </div>
              </div>
            </div>

            <!-- Timer Icon -->
            <div style="text-align: center; margin: 30px 0;">
              <div style="display: inline-block; background: #fef3c7; padding: 15px; border-radius: 50%;">
                <div style="font-size: 32px;">⏰</div>
              </div>
            </div>

            <!-- Time Notice -->
            <div style="background: #f1f5f9; padding: 20px; border-radius: 12px; margin: 25px 0; text-align: center;">
              <h3 style="color: #1e40af; font-size: 18px; margin: 0 0 10px 0; font-weight: 600;">
                Expires in 5 minutes
              </h3>
              <p style="color: #475569; font-size: 14px; margin: 0; line-height: 1.5;">
                For security reasons, this code will expire soon. Please use it immediately.
              </p>
            </div>

            <!-- Instructions -->
            <div style="margin: 30px 0;">
              <h3 style="color: #1e40af; font-size: 18px; margin: 0 0 15px 0; text-align: center; font-weight: 600;">
                How to use this code:
              </h3>
              <div style="display: flex; justify-content: center; flex-wrap: wrap; gap: 15px; margin-top: 20px;">
                <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 15px; width: 150px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
                  <div style="font-size: 24px; margin-bottom: 10px;">📋</div>
                  <div style="font-size: 14px; color: #475569;">Copy the code</div>
                </div>
                <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 15px; width: 150px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
                  <div style="font-size: 24px; margin-bottom: 10px;">💻</div>
                  <div style="font-size: 14px; color: #475569;">Paste on website</div>
                </div>
                <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 15px; width: 150px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
                  <div style="font-size: 24px; margin-bottom: 10px;">✅</div>
                  <div style="font-size: 14px; color: #475569;">Verify account</div>
                </div>
              </div>
            </div>

            <!-- Security Notice -->
            <div style="background: #fef3c7; border-left: 5px solid #f59e0b; padding: 20px; border-radius: 0 12px 12px 0; margin: 30px 0;">
              <div style="display: flex; align-items: flex-start;">
                <div style="font-size: 24px; margin-right: 15px; color: #f59e0b;">⚠️</div>
                <div>
                  <h4 style="color: #92400e; margin: 0 0 8px 0; font-size: 16px; font-weight: 600;">Security Notice</h4>
                  <p style="color: #92400e; font-size: 14px; margin: 0; line-height: 1.5;">
                    <strong>Do not share this code with anyone.</strong> MedScore will never ask for this code via phone or email.
                  </p>
                </div>
              </div>
            </div>

            <!-- Footer -->
            <div style="text-align: center; margin-top: 40px; padding-top: 25px; border-top: 1px solid #e2e8f0;">
              <p style="color: #64748b; font-size: 14px; margin: 0 0 10px 0;">
                © 2025 MedScore. All rights reserved.
              </p>
              <p style="color: #94a3b8; font-size: 13px; margin: 0; line-height: 1.5;">
                India's #1 NEET College Predictor & Mentorship Platform<br>
                If you didn't request this code, please ignore this email.
              </p>
            </div>
          </div>
        </div>
      </div>
    `;

    // Verify transporter configuration
    await transporter.verify();

    // Determine FROM email based on service (Bug #32 fix)
    let fromEmail;
    if (selectedService === "brevo") {
      // For Brevo, use BREVO_SMTP_USER (pre-verified sender)
      fromEmail = process.env.BREVO_SMTP_USER || "noreply@medscore.xyz";
    } else if (selectedService === "gmail") {
      fromEmail =
        process.env.GMAIL_USER ||
        process.env.FROM_EMAIL ||
        "noreply@medscore.xyz";
    } else if (selectedService === "outlook") {
      fromEmail =
        process.env.OUTLOOK_USER ||
        process.env.FROM_EMAIL ||
        "noreply@medscore.xyz";
    } else {
      fromEmail = process.env.FROM_EMAIL || "noreply@medscore.xyz";
    }

    // Send email
    const mailInfo = await transporter.sendMail({
      from: `"MedScore" <${fromEmail}>`,
      to: email,
      subject: `${subject} - MedScore`,
      html: message,
    });

    console.log(
      `✅ OTP email sent successfully to ${email}. MessageID: ${mailInfo.messageId}`,
    );
    return {
      success: true,
      message: "OTP sent successfully",
      messageId: mailInfo.messageId,
    };
  } catch (error) {
    console.error("Error in sendOTP function:", error);

    // Log specific error details for debugging
    console.error("Email service config:", {
      service: process.env.EMAIL_SERVICE,
      brevo_host: process.env.BREVO_SMTP_HOST,
      brevo_user: process.env.BREVO_SMTP_USER,
      gmail_user: process.env.GMAIL_USER,
      outlook_user: process.env.OUTLOOK_USER,
    });

    // Return error response instead of throwing
    return {
      success: false,
      message: "Failed to send OTP: " + error.message,
    };
  }
};

// Add JSON storage for OTPs as fallback
const fs = require("fs");
const path = require("path");

// Ensure data directory exists
const dataDir = path.join(__dirname, "../data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const otpFilePath = path.join(dataDir, "otps.json");

// Load OTPs from JSON file
const loadOTPs = () => {
  try {
    if (fs.existsSync(otpFilePath)) {
      const data = fs.readFileSync(otpFilePath, "utf8");
      return JSON.parse(data);
    }
    return [];
  } catch (error) {
    console.error("Error loading OTPs:", error);
    return [];
  }
};

// Save OTPs to JSON file
const saveOTPs = (otps) => {
  try {
    fs.writeFileSync(otpFilePath, JSON.stringify(otps, null, 2));
    return true;
  } catch (error) {
    console.error("Error saving OTPs:", error);
    return false;
  }
};

// Generate unique ID
const generateId = () => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
};

/**
 * Resolve identifier to email (Bug #13 fix - extracted common function)
 */
const resolveIdentifierToEmail = async (identifier) => {
  // Handle different types of identifiers
  if (typeof identifier === "string") {
    // Check if it's an email directly (for pre-signup verification)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (emailRegex.test(identifier)) {
      return identifier;
    } else if (identifier.startsWith("temp_")) {
      // For temporary tokens, we'll use the identifier directly as email identifier
      return identifier;
    } else {
      // It might be a user ID, try to find user
      try {
        const [userRows] = await pool.execute(
          "SELECT email FROM users WHERE id = ?",
          [identifier],
        );

        if (userRows.length === 0) {
          throw new Error("User not found");
        }

        return userRows[0].email;
      } catch (err) {
        // If it fails, treat it as email directly
        return identifier;
      }
    }
  } else {
    // For numeric user IDs
    const [userRows] = await pool.execute(
      "SELECT email FROM users WHERE id = ?",
      [identifier],
    );

    if (userRows.length === 0) {
      throw new Error("User not found");
    }

    return userRows[0].email;
  }
};

/**
 * Store OTP in database (with JSON fallback)
 */
const storeOTP = async (identifier, otp, type = "login") => {
  try {
    // Use extracted function (Bug #13 fix)
    const userEmail = await resolveIdentifierToEmail(identifier);

    // Try to store in database first
    try {
      // Don't delete old OTPs - let them expire naturally
      // User can request multiple OTPs, old ones will auto-expire

      // Create new OTP with proper expiry (10 minutes from NOW in MySQL timezone)
      // Use DATE_ADD to ensure MySQL handles timezone correctly
      await pool.execute(
        "INSERT INTO otps (email, otp, expires_at, type, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), ?, NOW())",
        [userEmail, otp, type],
      );

      console.log(
        `✅ OTP stored successfully in database for ${userEmail}, type: ${type}, expires in 10 minutes`,
      );
      return { success: true, message: "OTP stored successfully" };
    } catch (dbError) {
      console.error("❌ Database error in storeOTP:", dbError.message);
      // Database failed, use JSON fallback
      console.warn("⚠️ Database unavailable, using JSON storage for OTP");

      // Load existing OTPs
      let otps = loadOTPs();

      // Don't remove old OTPs - they will expire naturally
      // User can have multiple active OTPs

      // Create new OTP with proper expiry (10 minutes)
      const expiryTime = new Date(Date.now() + 10 * 60 * 1000);
      const newOTP = {
        id: generateId(),
        email: userEmail,
        otp: otp,
        type: type,
        expires_at: expiryTime.toISOString(),
        is_used: false,
        created_at: new Date().toISOString(),
      };

      // Add new OTP
      otps.push(newOTP);

      // Save to JSON file
      if (saveOTPs(otps)) {
        console.log(
          `✅ OTP stored successfully in JSON for ${userEmail}, type: ${type}, expires in 10 minutes`,
        );
        return { success: true, message: "OTP stored successfully" };
      } else {
        throw new Error("Failed to save OTP to JSON storage");
      }
    }
  } catch (error) {
    console.error("❌ Error storing OTP:", error);
    return { success: false, message: "Failed to store OTP: " + error.message };
  }
};

/**
 * Verify OTP (with JSON fallback)
 */
const verifyOTP = async (identifier, otp, type = "login") => {
  try {
    // Use extracted function (Bug #13 fix)
    let userEmail;
    try {
      userEmail = await resolveIdentifierToEmail(identifier);
    } catch (err) {
      return { valid: false, message: "User not found" };
    }

    console.log(
      `🔍 Verifying OTP for ${userEmail}, OTP: ${otp}, type: ${type}`,
    );

    // Try to verify from database first
    try {
      // Find the most recent matching OTP that hasn't been used and hasn't expired
      const [otpRows] = await pool.execute(
        "SELECT * FROM otps WHERE email = ? AND otp = ? AND type = ? AND is_used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1",
        [userEmail, otp, type],
      );

      if (otpRows.length > 0) {
        const otpRecord = otpRows[0];
        console.log(
          `✅ OTP verified successfully in database for ${userEmail}`,
        );

        // Mark THIS OTP as used (not all OTPs for this email)
        await pool.execute("UPDATE otps SET is_used = TRUE WHERE id = ?", [
          otpRecord.id,
        ]);

        return { valid: true, message: "OTP verified successfully" };
      }

      // Check if OTP exists but is expired or already used
      const [existingRows] = await pool.execute(
        "SELECT * FROM otps WHERE email = ? AND otp = ? AND type = ? ORDER BY created_at DESC LIMIT 1",
        [userEmail, otp, type],
      );

      if (existingRows.length > 0) {
        const existingOTP = existingRows[0];
        if (existingOTP.is_used) {
          return {
            valid: false,
            message: "OTP has already been used. Please request a new one.",
          };
        }
        if (new Date(existingOTP.expires_at) <= new Date()) {
          return {
            valid: false,
            message: "OTP has expired. Please request a new one.",
          };
        }
      }
    } catch (dbError) {
      // Database failed, use JSON fallback
      console.warn(
        "⚠️ Database unavailable, using JSON storage for OTP verification",
      );
    }

    // Try JSON storage as fallback
    let otps = loadOTPs();

    // Find most recent matching OTP that's valid
    const validOTPs = otps
      .filter(
        (otpRecord) =>
          otpRecord.email === userEmail &&
          otpRecord.otp === otp &&
          otpRecord.type === type &&
          !otpRecord.is_used &&
          new Date(otpRecord.expires_at) > new Date(),
      )
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const matchingOTP = validOTPs.length > 0 ? validOTPs[0] : null;

    if (matchingOTP) {
      console.log(`✅ OTP verified successfully in JSON for ${userEmail}`);

      // Mark OTP as used
      matchingOTP.is_used = true;
      saveOTPs(otps);

      return { valid: true, message: "OTP verified successfully" };
    }

    // Check if OTP exists but is expired or used
    const existingOTP = otps
      .filter(
        (otpRecord) =>
          otpRecord.email === userEmail &&
          otpRecord.otp === otp &&
          otpRecord.type === type,
      )
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];

    if (existingOTP) {
      if (existingOTP.is_used) {
        return {
          valid: false,
          message: "OTP has already been used. Please request a new one.",
        };
      }
      if (new Date(existingOTP.expires_at) <= new Date()) {
        return {
          valid: false,
          message: "OTP has expired. Please request a new one.",
        };
      }
    }

    return {
      valid: false,
      message: "Invalid OTP. Please check and try again.",
    };
  } catch (error) {
    console.error("❌ Error verifying OTP:", error);
    return { valid: false, message: "Failed to verify OTP: " + error.message };
  }
};

module.exports = {
  generateOTP,
  sendOTP,
  storeOTP,
  verifyOTP,
  resolveIdentifierToEmail,
};
