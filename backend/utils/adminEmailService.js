const nodemailer = require('nodemailer');

class AdminEmailService {
  constructor() {
    this.transporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
      }
    });
  }

  /**
   * Send admin notification email
   */
  async sendAdminNotification(type, data) {
    try {
      const adminEmails = [
        'admin@medscore.xyz',
        'content@medscore.xyz',
        'support@medscore.xyz'
      ];

      const emailContent = this.getEmailContent(type, data);
      
      for (const email of adminEmails) {
        await this.transporter.sendMail({
          from: process.env.GMAIL_USER,
          to: email,
          subject: emailContent.subject,
          html: emailContent.html
        });
      }

      console.log(`Admin notification sent for: ${type}`);
    } catch (error) {
      console.error('Admin email error:', error);
    }
  }

  /**
   * Get email content based on type
   */
  getEmailContent(type, data) {
    switch (type) {
      case 'new_user_registration':
        return {
          subject: 'New User Registration - MedScore',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">New User Registration</h2>
              <p>A new user has registered on MedScore:</p>
              <ul>
                <li><strong>Name:</strong> ${data.name}</li>
                <li><strong>Email:</strong> ${data.email}</li>
                <li><strong>Registration Date:</strong> ${new Date().toLocaleString()}</li>
              </ul>
              <p>Please review the user profile in the admin panel.</p>
            </div>
          `
        };

      case 'mentor_application':
        return {
          subject: 'New Mentor Application - MedScore',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">New Mentor Application</h2>
              <p>A new mentor has applied to join MedScore:</p>
              <ul>
                <li><strong>Name:</strong> ${data.name}</li>
                <li><strong>Email:</strong> ${data.email}</li>
                <li><strong>Qualification:</strong> ${data.qualification}</li>
                <li><strong>Experience:</strong> ${data.experience} years</li>
                <li><strong>Application Date:</strong> ${new Date().toLocaleString()}</li>
              </ul>
              <p>Please review the application in the admin panel.</p>
            </div>
          `
        };

      case 'payment_received':
        return {
          subject: 'Payment Received - MedScore',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">Payment Received</h2>
              <p>A new payment has been received:</p>
              <ul>
                <li><strong>Amount:</strong> ₹${data.amount}</li>
                <li><strong>User:</strong> ${data.userName}</li>
                <li><strong>Service:</strong> ${data.service}</li>
                <li><strong>Payment ID:</strong> ${data.paymentId}</li>
                <li><strong>Date:</strong> ${new Date().toLocaleString()}</li>
              </ul>
            </div>
          `
        };

      case 'system_error':
        return {
          subject: 'System Error Alert - MedScore',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #d32f2f;">System Error Alert</h2>
              <p>A system error has occurred:</p>
              <ul>
                <li><strong>Error:</strong> ${data.error}</li>
                <li><strong>Location:</strong> ${data.location}</li>
                <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
              </ul>
              <p>Please check the system logs for more details.</p>
            </div>
          `
        };

      case 'daily_report':
        return {
          subject: 'Daily Report - MedScore',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">Daily Report - ${new Date().toLocaleDateString()}</h2>
              <h3>Statistics:</h3>
              <ul>
                <li><strong>New Users:</strong> ${data.newUsers}</li>
                <li><strong>New Mentors:</strong> ${data.newMentors}</li>
                <li><strong>Total Revenue:</strong> ₹${data.revenue}</li>
                <li><strong>Active Sessions:</strong> ${data.activeSessions}</li>
              </ul>
              <p>View detailed analytics in the admin panel.</p>
            </div>
          `
        };

      default:
        return {
          subject: 'MedScore Notification',
          html: `<p>Notification: ${JSON.stringify(data)}</p>`
        };
    }
  }

  /**
   * Send welcome email to new admin
   */
  async sendAdminWelcomeEmail(adminEmail, adminName, tempPassword) {
    try {
      await this.transporter.sendMail({
        from: process.env.GMAIL_USER,
        to: adminEmail,
        subject: 'Welcome to MedScore Admin Panel',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Welcome to MedScore Admin Panel</h2>
            <p>Hello ${adminName},</p>
            <p>Your admin account has been created successfully.</p>
            <p><strong>Login Details:</strong></p>
            <ul>
              <li><strong>Email:</strong> ${adminEmail}</li>
              <li><strong>Temporary Password:</strong> ${tempPassword}</li>
            </ul>
            <p>Please login at: <a href="https://medscore.xyz/pages/admin-login.html">Admin Login</a></p>
            <p>For security reasons, please change your password after first login.</p>
            <p>Best regards,<br>MedScore Team</p>
          </div>
        `
      });
    } catch (error) {
      console.error('Admin welcome email error:', error);
    }
  }

  /**
   * Send password reset email to admin
   */
  async sendAdminPasswordReset(adminEmail, resetToken) {
    try {
      await this.transporter.sendMail({
        from: process.env.GMAIL_USER,
        to: adminEmail,
        subject: 'Password Reset - MedScore Admin',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Password Reset Request</h2>
            <p>You have requested a password reset for your admin account.</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="https://medscore.xyz/pages/admin-reset-password.html?token=${resetToken}" 
                  style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              Reset Password
            </a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
        `
      });
    } catch (error) {
      console.error('Admin password reset email error:', error);
    }
  }
}

module.exports = new AdminEmailService();
