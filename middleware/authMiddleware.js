const jwt = require("jsonwebtoken");
const { findUserById, findUserByEmail } = require("../services/userStore");

const JWT_SECRET = process.env.JWT_SECRET || "rahila_kareem_super_secret_jwt_key_2026_secured";

/**
 * Authentication Middleware:
 * Validates JWT from HttpOnly cookie or Authorization Bearer header.
 * Enforces that user exists and isVerified === true.
 */
async function authenticateUser(req, res, next) {
  try {
    let token = null;

    // 1. Check HttpOnly cookie
    if (req.cookies && req.cookies.auth_token) {
      token = req.cookies.auth_token;
    }

    // 2. Check Authorization Bearer header
    if (!token && req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in to access this resource."
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          success: false,
          code: "TOKEN_EXPIRED",
          message: "Your session has expired. Please log in again."
        });
      }
      return res.status(401).json({
        success: false,
        message: "Invalid session token. Please log in again."
      });
    }

    // Retrieve user via userStore (MongoDB or resilient store)
    let user = await findUserById(decoded.id);
    if (!user && decoded.email) {
      user = await findUserByEmail(decoded.email);
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User session invalid. Account not found."
      });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        code: "UNVERIFIED_EMAIL",
        message: "Email verification required. Please verify your email before accessing your workspace."
      });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(500).json({ success: false, message: "Internal authentication error." });
  }
}

/**
 * Authorization Middleware: Enforce Admin Role
 */
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ success: false, message: "Authentication required." });
  }

  const authorizedEmails = ["wordpressrahila@gmail.com", "rahilakareem389@gmail.com"];
  const isAdmin = req.user.role === "Admin" || authorizedEmails.includes(req.user.email?.toLowerCase());

  if (!isAdmin) {
    return res.status(403).json({
      success: false,
      message: "Access Denied: Administrator privileges required."
    });
  }

  next();
}

module.exports = {
  authenticateUser,
  requireAdmin,
  JWT_SECRET
};
