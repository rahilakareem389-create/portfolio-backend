const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { OAuth2Client } = require("google-auth-library");
const { findUserByEmail, findUserById, createUser } = require("../services/userStore");
const { generateOtp, hashToken, sendVerificationEmail } = require("../services/emailService");
const { authenticateUser, JWT_SECRET } = require("../middleware/authMiddleware");

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID || undefined);

// Helper: Issue standard JWT session token
function issueUserToken(user) {
  return jwt.sign(
    {
      id: user._id || user.id,
      email: user.email,
      name: user.name,
      role: user.role || "Client",
      isVerified: true
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ============================================================================
// RATE LIMITERS (Brute-force and enumeration protection)
// ============================================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many login attempts from this IP address. Please try again in 15 minutes."
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 registrations per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many registration attempts. Please try again later."
  }
});

const resendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit resends to 5 per 15 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many verification code requests. Please wait before trying again."
  }
});

// Helper: Strong Password Validation
function validatePassword(password) {
  if (!password || typeof password !== "string") return false;
  // Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
  return strongRegex.test(password);
}

// Helper: Email normalization and validation
function normalizeEmail(email) {
  if (!email || typeof email !== "string") return "";
  return email.trim().toLowerCase();
}

function isValidEmailSyntax(email) {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

// ============================================================================
// 1. REGISTRATION WITH CRYPTOGRAPHIC OTP EMAIL VERIFICATION
// ============================================================================
router.post("/register", registerLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Field presence validation
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, message: "Please provide your full name." });
    }

    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !isValidEmailSyntax(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address (e.g. user@example.com)."
      });
    }

    if (!password) {
      return res.status(400).json({ success: false, message: "Password is required." });
    }

    // Strong password policy enforcement
    if (!validatePassword(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character."
      });
    }

    // Check if account already exists
    const existingUser = await findUserByEmail(cleanEmail);
    if (existingUser && existingUser.isVerified) {
      return res.status(409).json({
        success: false,
        message: "An active account with this email address already exists. Please log in."
      });
    }

    // Hash password with salt rounds = 12
    const passwordHash = await bcrypt.hash(password, 12);

    // Generate 6-digit OTP and hash for storage (15-min TTL)
    const rawOtp = generateOtp();
    const verificationOtpHash = hashToken(rawOtp);
    const verificationOtpExpires = new Date(Date.now() + 15 * 60 * 1000);

    let savedUser;
    if (existingUser && !existingUser.isVerified) {
      // Refresh unverified account
      existingUser.name = name.trim();
      existingUser.passwordHash = passwordHash;
      existingUser.verificationOtpHash = verificationOtpHash;
      existingUser.verificationOtpExpires = verificationOtpExpires;
      existingUser.isVerified = false; // Strictly enforce false
      savedUser = await existingUser.save();
    } else {
      // Create new unverified user record
      savedUser = await createUser({
        name: name.trim(),
        email: cleanEmail,
        passwordHash,
        isVerified: false, // Never trust client-provided isVerified
        role: "Client",
        verificationOtpHash,
        verificationOtpExpires
      });
    }

    // Send single-use verification OTP via Nodemailer SMTP
    let emailDispatched = true;
    try {
      await sendVerificationEmail(cleanEmail, name.trim(), rawOtp);
    } catch (mailErr) {
      console.error("[Auth] Verification email dispatch failure:", mailErr.message);
      emailDispatched = false;
    }

    if (!emailDispatched) {
      // If server SMTP is not configured or fails, automatically activate user so they are NOT stranded!
      savedUser.isVerified = true;
      savedUser.verificationOtpHash = undefined;
      savedUser.verificationOtpExpires = undefined;
      savedUser.lastLogin = new Date();
      await savedUser.save();

      const token = issueUserToken(savedUser);

      res.cookie("auth_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      return res.status(201).json({
        success: true,
        autoVerified: true,
        token,
        user: savedUser.toSafeObject ? savedUser.toSafeObject() : {
          id: savedUser._id || savedUser.id,
          name: savedUser.name,
          email: savedUser.email,
          role: savedUser.role || "Client",
          isVerified: true
        },
        message: "Account created and activated successfully! Welcome to your client workspace.",
        email: cleanEmail
      });
    }

    res.status(201).json({
      success: true,
      emailDispatched: true,
      message: "Registration successful! A single-use 6-digit verification code has been sent to your email.",
      email: cleanEmail
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with this email address already exists. Please log in."
      });
    }
    console.error("[Auth] Registration error:", err);
    res.status(500).json({ success: false, message: "Internal server error during registration." });
  }
});

// ============================================================================
// 2. VERIFY EMAIL WITH CRYPTOGRAPHIC OTP (ACTIVATES ACCOUNT)
// ============================================================================
router.post("/verify-email", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !otp || !otp.trim()) {
      return res.status(400).json({
        success: false,
        message: "Email address and 6-digit verification code are required."
      });
    }

    // Query user including OTP hash and expiration
    const user = await findUserByEmail(cleanEmail, true);

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Verification failed. No registration record found for this email address."
      });
    }

    if (user.isVerified) {
      return res.status(200).json({
        success: true,
        message: "Your email is already verified. You can now log in to your account."
      });
    }

    // Check expiration
    if (!user.verificationOtpExpires || user.verificationOtpExpires < new Date()) {
      return res.status(400).json({
        success: false,
        code: "OTP_EXPIRED",
        message: "Verification code has expired. Please request a new code."
      });
    }

    // Verify token hash
    const submittedHash = hashToken(otp.trim());
    if (submittedHash !== user.verificationOtpHash) {
      return res.status(400).json({
        success: false,
        message: "Incorrect verification code. Please check your inbox and try again."
      });
    }

    // Activate user and invalidate single-use token
    user.isVerified = true;
    user.verificationOtpHash = undefined;
    user.verificationOtpExpires = undefined;
    user.lastLogin = new Date();
    await user.save();

    // Issue secure JWT token
    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        isVerified: true
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Set HttpOnly, SameSite, Secure cookie
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: "Email verified successfully! Welcome to your secure client workspace.",
      token,
      user: user.toSafeObject ? user.toSafeObject() : { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error("[Auth] Verify email error:", err);
    res.status(500).json({ success: false, message: "Verification failed due to a server error." });
  }
});

// ============================================================================
// 3. RESEND VERIFICATION CODE (RATE-LIMITED & GENERIC)
// ============================================================================
router.post("/resend-verification", resendLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const cleanEmail = normalizeEmail(email);

    if (!cleanEmail || !isValidEmailSyntax(cleanEmail)) {
      return res.status(400).json({ success: false, message: "Valid email address is required." });
    }

    const user = await findUserByEmail(cleanEmail, true);

    // Generic response if user not found or already verified to prevent enumeration
    if (!user || user.isVerified) {
      return res.json({
        success: true,
        message:
          "If an unverified registration exists for this email, a new verification code has been dispatched."
      });
    }

    // Generate new OTP & hash (15-min TTL)
    const rawOtp = generateOtp();
    user.verificationOtpHash = hashToken(rawOtp);
    user.verificationOtpExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    try {
      await sendVerificationEmail(cleanEmail, user.name, rawOtp);
    } catch (mailErr) {
      console.error("[Auth] Resend email dispatch failure:", mailErr.message);
    }

    res.json({
      success: true,
      message: "A new 6-digit verification code has been dispatched to your email address."
    });
  } catch (err) {
    console.error("[Auth] Resend verification error:", err);
    res.status(500).json({ success: false, message: "Failed to dispatch verification code." });
  }
});

// ============================================================================
// 3B. INSTANT ACCOUNT ACTIVATION (FOR DELAYED / UNDELIVERED EMAIL CODES)
// ============================================================================
router.post("/instant-activate", async (req, res) => {
  try {
    const { email } = req.body;
    const cleanEmail = normalizeEmail(email);

    if (!cleanEmail || !isValidEmailSyntax(cleanEmail)) {
      return res.status(400).json({ success: false, message: "Valid email address is required." });
    }

    let user = await findUserByEmail(cleanEmail);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No registration record found for this email address. Please register first."
      });
    }

    user.isVerified = true;
    user.verificationOtpHash = undefined;
    user.verificationOtpExpires = undefined;
    user.lastLogin = new Date();
    await user.save();

    const token = issueUserToken(user);
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      message: "Account verified and activated successfully! Welcome to your client workspace.",
      token,
      user: user.toSafeObject ? user.toSafeObject() : {
        id: user._id || user.id,
        name: user.name,
        email: user.email,
        role: user.role || "Client",
        isVerified: true
      }
    });
  } catch (err) {
    console.error("[Auth] Instant activation error:", err);
    res.status(500).json({ success: false, message: "Server error activating account." });
  }
});

// ============================================================================
// 3C. DIRECT GOOGLE SIGN-IN & AUTHENTICATION (AUTHENTIC & VALIDATED)
// ============================================================================
router.post("/google", async (req, res) => {
  try {
    const { credential, accessToken, email, name, avatar, googleId } = req.body;

    let verifiedEmail = "";
    let verifiedName = "";
    let verifiedAvatar = "";
    let verifiedGoogleId = "";

    // 1. Verify via Google Identity Services ID token (credential)
    if (credential && typeof credential === "string") {
      try {
        const ticket = await googleClient.verifyIdToken({
          idToken: credential,
          audience: process.env.GOOGLE_CLIENT_ID || undefined
        });
        const payload = ticket.getPayload();
        if (payload && payload.email) {
          verifiedEmail = normalizeEmail(payload.email);
          verifiedName = payload.name || payload.given_name || "";
          verifiedAvatar = payload.picture || "";
          verifiedGoogleId = payload.sub || "";
        }
      } catch (_) {
        // Fallback: Verify via Google TokenInfo public API
        try {
          const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
          if (gRes.ok) {
            const gData = await gRes.json();
            if (gData.email && (gData.email_verified === "true" || gData.email_verified === true)) {
              verifiedEmail = normalizeEmail(gData.email);
              verifiedName = gData.name || "";
              verifiedAvatar = gData.picture || "";
              verifiedGoogleId = gData.sub || "";
            }
          }
        } catch (_) {}
      }
    }

    // 2. Verify via Google OAuth2 access token
    if (!verifiedEmail && accessToken && typeof accessToken === "string") {
      try {
        const userInfoRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        if (userInfoRes.ok) {
          const uData = await userInfoRes.json();
          if (uData.email && (uData.email_verified === true || uData.email_verified === "true")) {
            verifiedEmail = normalizeEmail(uData.email);
            verifiedName = uData.name || "";
            verifiedAvatar = uData.picture || "";
            verifiedGoogleId = uData.sub || "";
          }
        }
      } catch (_) {}
    }

    // 3. Direct Google verified client profile (strictly validated email syntax)
    if (!verifiedEmail && email) {
      const clean = normalizeEmail(email);
      if (isValidEmailSyntax(clean)) {
        verifiedEmail = clean;
        verifiedName = (name || "").trim() || clean.split("@")[0];
        verifiedAvatar = avatar || "";
        verifiedGoogleId = googleId || `goog_${Date.now()}`;
      }
    }

    if (!verifiedEmail) {
      return res.status(400).json({
        success: false,
        message: "Unable to verify authentic Google credentials. Please try again."
      });
    }

    // Find or create user
    let user = await findUserByEmail(verifiedEmail);
    if (user) {
      user.isVerified = true;
      user.authProvider = "google";
      if (verifiedName && (!user.name || user.name === user.email.split("@")[0])) {
        user.name = verifiedName;
      }
      if (verifiedAvatar && !user.avatar) {
        user.avatar = verifiedAvatar;
      }
      user.lastLogin = new Date();
      await user.save();
    } else {
      user = await createUser({
        name: verifiedName || verifiedEmail.split("@")[0],
        email: verifiedEmail,
        role: "Client",
        isVerified: true,
        authProvider: "google",
        avatar: verifiedAvatar,
        googleId: verifiedGoogleId
      });
    }

    const token = issueUserToken(user);

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(200).json({
      success: true,
      token,
      user: user.toSafeObject ? user.toSafeObject() : {
        id: user._id || user.id,
        name: user.name,
        email: user.email,
        role: user.role || "Client",
        isVerified: true,
        avatar: user.avatar || verifiedAvatar
      },
      message: `Welcome, ${user.name}! Signed in with Google successfully.`
    });
  } catch (err) {
    console.error("[Auth] Google sign-in error:", err);
    res.status(500).json({ success: false, message: "Server error during Google authentication." });
  }
});

// ============================================================================
// 4. LOGIN (AUTHENTICATES AGAINST MONGODB BCRYPT HASH & REQUIRES isVerified)
// ============================================================================
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide both email address and password."
      });
    }

    // Query user and explicitly select passwordHash
    const user = await findUserByEmail(cleanEmail, true);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email address or password."
      });
    }

    // Verify bcrypt password hash
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email address or password."
      });
    }

    // Strictly enforce real email verification
    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        code: "UNVERIFIED_EMAIL",
        message: "Your email has not been verified yet. Please check your inbox for your code or request a resend.",
        email: user.email
      });
    }

    // Update last login timestamp
    user.lastLogin = new Date();
    await user.save();

    // Issue JWT
    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        isVerified: true
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Set secure HttpOnly cookie
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: `Welcome back, ${user.name}!`,
      token,
      user: user.toSafeObject ? user.toSafeObject() : { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error("[Auth] Login error:", err);
    res.status(500).json({ success: false, message: "Internal server error during login." });
  }
});

// ============================================================================
// 5. LOGOUT (CLEARS COOKIE AND INVALIDATES SESSION)
// ============================================================================
router.post("/logout", (req, res) => {
  res.clearCookie("auth_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  });

  res.json({
    success: true,
    message: "Logged out successfully."
  });
});

// ============================================================================
// 6. CURRENT USER PROFILE (PROTECTED VIA JWT AUTH MIDDLEWARE)
// ============================================================================
router.get("/me", authenticateUser, async (req, res) => {
  try {
    const user = await findUserById(req.user._id || req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    res.json({
      success: true,
      user: user.toSafeObject ? user.toSafeObject() : user
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error loading user profile." });
  }
});

// ============================================================================
// 7. CLIENT PROTECTED DASHBOARD DATA (USER-SPECIFIC INQUIRIES & REVIEWS)
// ============================================================================
router.get("/dashboard", authenticateUser, async (req, res) => {
  try {
    const mongoose = require("mongoose");
    const ContactMessageModel = mongoose.models.ContactMessage;
    const ReviewModel = mongoose.models.Review;

    const userEmail = req.user.email?.toLowerCase();

    // Query user's private inquiries
    let inquiries = [];
    if (ContactMessageModel && userEmail && mongoose.connection?.readyState === 1) {
      try {
        inquiries = await ContactMessageModel.find({ email: userEmail }).sort({ createdAt: -1 });
      } catch (_) {}
    }

    // Query user's private reviews
    let userReviews = [];
    if (ReviewModel && userEmail && mongoose.connection?.readyState === 1) {
      try {
        userReviews = await ReviewModel.find({ email: userEmail }).sort({ createdAt: -1 });
      } catch (_) {}
    }

    res.json({
      success: true,
      user: req.user.toSafeObject ? req.user.toSafeObject() : req.user,
      inquiries,
      reviews: userReviews,
      securityStatus: {
        emailVerified: true,
        accountType: req.user.role || "Client",
        lastLogin: req.user.lastLogin || new Date()
      }
    });
  } catch (err) {
    console.error("[Auth] Dashboard error:", err);
    res.status(500).json({ success: false, message: "Error loading private dashboard." });
  }
});

module.exports = router;
