const nodemailer = require("nodemailer");
const crypto = require("crypto");

// Create single reusable transporter using environment SMTP configuration
function getTransporter() {
  const host = process.env.SMTP_HOST || "smtp.gmail.com";
  const port = Number(process.env.SMTP_PORT) || 465;
  const secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === "true" : port === 465;
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS ? process.env.EMAIL_PASS.replace(/\s+/g, "") : "";

  if (!user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass
    },
    tls: {
      rejectUnauthorized: process.env.NODE_ENV === "production"
    }
  });
}

// Generate a cryptographically secure 6-digit numeric OTP
function generateOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

// Compute single-direction SHA-256 hash of OTP for storage
function hashToken(token) {
  return crypto.createHash("sha256").update(token.trim()).digest("hex");
}

/**
 * Dispatches verification email containing single-use OTP
 * @param {string} toEmail - Recipient email address
 * @param {string} recipientName - Recipient's name
 * @param {string} otp - Unhashed 6-digit OTP
 */
async function sendVerificationEmail(toEmail, recipientName, otp) {
  const transporter = getTransporter();
  const senderEmail = process.env.EMAIL_USER || "wordpressrahila@gmail.com";
  const brandName = "Rahila Kareem • Client Workspace";

  if (!transporter) {
    console.warn("[EmailService] SMTP transporter not configured (EMAIL_USER / EMAIL_PASS missing).");
    throw new Error("Email delivery service is currently not configured on the server.");
  }

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Verify Your Email Address</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #0e0805; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #ffffff;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0e0805; padding: 30px 15px;">
          <tr>
            <td align="center">
              <table width="100%" max-width="540" cellpadding="0" cellspacing="0" style="max-width: 540px; background-color: #170e0a; border: 1px solid #3d2419; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
                <tr>
                  <td style="padding: 35px 30px 20px 30px; text-align: center; border-bottom: 1px solid #291710; background: linear-gradient(180deg, #22140e 0%, #170e0a 100%);">
                    <h2 style="margin: 0; color: #ff7a1a; font-size: 20px; font-weight: 800; letter-spacing: -0.5px;">
                      ${brandName}
                    </h2>
                    <p style="margin: 6px 0 0 0; color: #a89486; font-size: 13px;">
                      Secure Email Ownership Verification
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 35px 30px;">
                    <p style="margin: 0 0 16px 0; color: #e5d8cf; font-size: 15px; line-height: 1.5;">
                      Hello <strong>${recipientName || "Valued Client"}</strong>,
                    </p>
                    <p style="margin: 0 0 24px 0; color: #bcab9e; font-size: 14px; line-height: 1.6;">
                      Thank you for registering. Please enter the single-use 6-digit verification code below to verify your email ownership and activate your secure client workspace.
                    </p>
                    
                    <div style="background-color: #24140c; border: 1px dashed #D57C63; border-radius: 12px; padding: 18px; text-align: center; margin: 25px 0;">
                      <span style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #ffffff; font-family: 'Courier New', monospace;">
                        ${otp}
                      </span>
                    </div>

                    <p style="margin: 0 0 12px 0; color: #bcab9e; font-size: 12.5px; line-height: 1.6;">
                      ⏱️ <strong>This code expires in 15 minutes</strong> and can only be used once.
                    </p>
                    <p style="margin: 0; color: #8a7569; font-size: 12px; line-height: 1.5;">
                      If you did not initiate this request, you can safely disregard this email. Your account will not be activated without this verification.
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 20px 30px; text-align: center; background-color: #120a07; border-top: 1px solid #291710; color: #6b5a50; font-size: 11px;">
                    © ${new Date().getFullYear()} Rahila Kareem • Full Stack Web Development &amp; SEO Strategy
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;

  const mailOptions = {
    from: `"${brandName}" <${senderEmail}>`,
    to: toEmail,
    subject: `${otp} is your verification code for Rahila Kareem Workspace`,
    text: `Your single-use verification code is: ${otp}. It expires in 15 minutes.`,
    html
  };

  return transporter.sendMail(mailOptions);
}

/**
 * Dispatches an automated email notification to the user whenever Admin replies/answers
 */
async function sendClientNotificationEmail({ toEmail, recipientName, type, subject, originalContent, replyContent }) {
  if (!toEmail) return false;

  const senderEmail = process.env.EMAIL_USER || "wordpressrahila@gmail.com";
  const brandName = "Rahila Kareem • Full Stack Web & SEO Specialist";

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>${subject || "Response from Rahila Kareem"}</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #0e0805; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #ffffff;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0e0805; padding: 30px 15px;">
          <tr>
            <td align="center">
              <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 580px; background-color: #170e0a; border: 1px solid #3d2419; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
                <tr>
                  <td style="padding: 30px 30px 20px 30px; text-align: center; border-bottom: 1px solid #291710; background: linear-gradient(180deg, #22140e 0%, #170e0a 100%);">
                    <h2 style="margin: 0; color: #D57C63; font-size: 20px; font-weight: 800; letter-spacing: -0.5px;">
                      ${brandName}
                    </h2>
                    <p style="margin: 6px 0 0 0; color: #a89486; font-size: 13px;">
                      Official Response Notification • ${type || "Update"}
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 30px;">
                    <p style="margin: 0 0 14px 0; color: #e5d8cf; font-size: 15px; line-height: 1.5;">
                      Hello <strong>${recipientName || "Valued Client"}</strong>,
                    </p>
                    <p style="margin: 0 0 20px 0; color: #bcab9e; font-size: 14px; line-height: 1.6;">
                      Rahila Kareem has reviewed and officially responded to your <strong>${type}</strong>:
                    </p>

                    ${originalContent ? `
                    <div style="background-color: #1e130d; border-left: 3px solid #6b5a50; padding: 12px 16px; margin: 0 0 20px 0; border-radius: 0 8px 8px 0;">
                      <p style="margin: 0 0 6px 0; color: #8a7569; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px;">
                        Your Original Submission:
                      </p>
                      <p style="margin: 0; color: #d6c7bc; font-size: 13px; font-style: italic; line-height: 1.5;">
                        "${originalContent}"
                      </p>
                    </div>
                    ` : ''}

                    <div style="background-color: #24140c; border: 1px solid #D57C63; border-radius: 12px; padding: 20px; margin: 0 0 24px 0;">
                      <div style="margin-bottom: 10px;">
                        <span style="display: inline-block; background-color: #D57C63; color: #000000; font-weight: 800; font-size: 10px; padding: 3px 8px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.5px;">
                          Official Response
                        </span>
                        <span style="color: #ff9a7b; font-size: 12px; font-weight: 600; margin-left: 8px;">
                          Rahila Kareem (Full Stack & SEO)
                        </span>
                      </div>
                      <p style="margin: 0; color: #ffffff; font-size: 14px; line-height: 1.6; font-weight: 500;">
                        ${replyContent}
                      </p>
                    </div>

                    <div style="text-align: center; margin: 30px 0 10px 0;">
                      <a href="https://portfolio-frontend-kappa-drab.vercel.app" style="display: inline-block; background: linear-gradient(135deg, #D57C63 0%, #b85d45 100%); color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 700; padding: 12px 28px; border-radius: 50px; box-shadow: 0 4px 15px rgba(213, 124, 99, 0.4);">
                        View Live on Portfolio Website →
                      </a>
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 20px 30px; text-align: center; background-color: #120a07; border-top: 1px solid #291710; color: #6b5a50; font-size: 11px;">
                    <p style="margin: 0 0 6px 0;">Rahila Kareem • Full Stack Web Development &amp; SEO Specialist</p>
                    <p style="margin: 0;">Direct WhatsApp: +92 321 7812265 • Email: wordpressrahila@gmail.com</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;

  // 1. Try sending directly to recipient via Nodemailer SMTP
  try {
    const transporter = getTransporter();
    if (transporter) {
      await transporter.sendMail({
        from: `"${brandName}" <${senderEmail}>`,
        to: toEmail,
        subject: subject || `Response from Rahila Kareem`,
        text: `Hello ${recipientName || 'Client'},\n\nRahila Kareem has responded to your ${type}:\n\n"${replyContent}"\n\nVisit: https://portfolio-frontend-kappa-drab.vercel.app`,
        html
      });
      console.log(`[EmailService] Notification successfully dispatched to ${toEmail}`);
      return true;
    }
  } catch (err) {
    console.warn(`[EmailService] Nodemailer dispatch notice for ${toEmail}:`, err.message);
  }

  return true;
}

module.exports = {
  generateOtp,
  hashToken,
  sendVerificationEmail,
  sendClientNotificationEmail
};
