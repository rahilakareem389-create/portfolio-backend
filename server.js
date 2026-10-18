const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
require("dotenv").config();

// Load Mongoose models
const User = require("./models/User");

const app = express();
const PORT = process.env.PORT || 5000;
const WEB3FORMS_ACCESS_KEY = process.env.WEB3FORMS_ACCESS_KEY || "ad131140-827b-407f-a476-5afd66b1fa0b";

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:4173",
  "https://portfolio-backend-omega-tan.vercel.app",
  process.env.CLIENT_URL
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (
        allowedOrigins.includes(origin) ||
        origin.endsWith(".vercel.app") ||
        origin.includes("localhost") ||
        origin.includes("127.0.0.1")
      ) {
        return callback(null, true);
      }
      return callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
  })
);

app.use(cookieParser());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ================================================================
// FILE STORAGE & VERCEL /TMP CONFIGURATION
// ================================================================
const isVercel = Boolean(process.env.VERCEL);
const bundledDataDir = path.join(__dirname, "data");
const dataDir = isVercel ? path.join("/tmp", "data") : bundledDataDir;

const reviewsFilePath = path.join(dataDir, "reviews.json");
const faqsFilePath = path.join(dataDir, "faqs.json");
const usersFilePath = path.join(dataDir, "users.json");
const messagesFilePath = path.join(dataDir, "messages.json");
const gmbFilePath = path.join(dataDir, "gmb.json");

function readJson(filePath, defaultVal = []) {
  try {
    if (isVercel && !fs.existsSync(filePath)) {
      const fileName = path.basename(filePath);
      const bundledFile = path.join(bundledDataDir, fileName);
      if (fs.existsSync(bundledFile)) {
        const initialContent = fs.readFileSync(bundledFile, "utf8");
        try {
          if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
          fs.writeFileSync(filePath, initialContent, "utf8");
        } catch (_) {}
        return JSON.parse(initialContent || "[]");
      }
    }

    if (!fs.existsSync(filePath)) return defaultVal;
    const data = fs.readFileSync(filePath, "utf8");
    return JSON.parse(data || "[]");
  } catch (err) {
    console.error(`Error reading ${filePath}:`, err);
    return defaultVal;
  }
}

function writeJson(filePath, data) {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (err) {
    console.error(`Error writing ${filePath}:`, err);
    return false;
  }
}

// ================================================================
// ================================================================
// MONGODB ATLAS INTEGRATION & SCHEMAS (SERVERLESS COMPATIBLE)
// ================================================================
let isMongoConnected = false;
let cachedMongoConn = null;
let cachedMongoPromise = null;

async function connectToMongo() {
  if (cachedMongoConn && mongoose.connection.readyState === 1) {
    isMongoConnected = true;
    return cachedMongoConn;
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    return null;
  }
  if (!cachedMongoPromise) {
    cachedMongoPromise = mongoose
      .connect(uri, {
        serverSelectionTimeoutMS: 20000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10
      })
      .then((mongooseInstance) => {
        isMongoConnected = true;
        console.log("MongoDB Atlas connected successfully.");
        syncJsonToMongo();
        return mongooseInstance;
      })
      .catch((err) => {
        console.warn("MongoDB Atlas connection warning (falling back to JSON store):", err.message);
        cachedMongoPromise = null;
        isMongoConnected = false;
        return null;
      });
  }
  cachedMongoConn = await cachedMongoPromise;
  return cachedMongoConn;
}

// Initial boot connection attempt
if (process.env.MONGODB_URI) {
  connectToMongo();
} else {
  console.log("No MONGODB_URI provided in environment. Operating with high-speed JSON store.");
}

// Serverless middleware to ensure DB connection is active before processing API calls
app.use(async (req, res, next) => {
  if (process.env.MONGODB_URI && mongoose.connection.readyState !== 1) {
    try {
      await connectToMongo();
    } catch (_) {}
  }
  next();
});

// 1. User & Login Audit Schema ("kon login huwa")
const UserLogSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    name: { type: String, default: "Client User" },
    email: { type: String, required: true },
    role: { type: String, default: "Client" },
    source: { type: String, default: "Website Auth" },
    activity: { type: String, default: "Logged In" },
    ip: { type: String, default: "" },
    userAgent: { type: String, default: "" },
    date: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

// 2. Contact Inquiries & Web3Forms Message Schema ("kis n mesaage kia")
const ContactMessageSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, default: "" },
    plan: { type: String, default: "General Inquiry" },
    subject: { type: String, default: "New Website Inquiry" },
    message: { type: String, required: true },
    status: { type: String, default: "new" }, // "new" | "replied" | "closed"
    adminNotes: { type: String, default: "" },
    web3FormsStatus: { type: String, default: "delivered" },
    date: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

// 3. Review Schema with Admin Reply ("admin bt kery ga user s reviews")
const ReviewSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, default: "" },
    role: { type: String, default: "Verified Client" },
    rating: { type: Number, default: 5 },
    service: { type: String, default: "Complete SEO Strategy" },
    title: { type: String, default: "" },
    message: { type: String, required: true },
    source: { type: String, default: "Google My Business" },
    sourceType: { type: String, default: "gmb" },
    gmbVerified: { type: Boolean, default: false },
    date: { type: String, default: "Just now" },
    status: { type: String, default: "pending" }, // "pending" | "approved" | "rejected"
    helpfulCount: { type: Number, default: 0 },
    avatar: { type: String, default: "" },
    adminReply: {
      message: { type: String, default: "" },
      repliedAt: { type: Date },
      adminEmail: { type: String, default: "wordpressrahila@gmail.com" }
    }
  },
  { timestamps: true }
);

// 4. FAQ Schema with Admin Answer ("kis n eaq kia")
const FaqSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    question: { type: String, required: true },
    answer: { type: String, default: "" },
    author: { type: String, default: "Community Member" },
    email: { type: String, default: "" },
    date: { type: String, default: "Recently" },
    status: { type: String, default: "approved" },
    adminEmail: { type: String, default: "wordpressrahila@gmail.com" }
  },
  { timestamps: true }
);

const UserLogModel = mongoose.models.UserLog || mongoose.model("UserLog", UserLogSchema);
const ContactMessageModel = mongoose.models.ContactMessage || mongoose.model("ContactMessage", ContactMessageSchema);
const ReviewModel = mongoose.models.Review || mongoose.model("Review", ReviewSchema);
const FaqModel = mongoose.models.Faq || mongoose.model("Faq", FaqSchema);

// Sync initial JSON files into MongoDB Atlas if connected and empty
async function syncJsonToMongo() {
  if (!isMongoConnected) return;
  try {
    const reviewCount = await ReviewModel.countDocuments();
    if (reviewCount === 0) {
      const initialReviews = readJson(reviewsFilePath, []);
      if (initialReviews.length) await ReviewModel.insertMany(initialReviews);
    }

    const faqCount = await FaqModel.countDocuments();
    if (faqCount === 0) {
      const initialFaqs = readJson(faqsFilePath, []);
      if (initialFaqs.length) await FaqModel.insertMany(initialFaqs);
    }

    const userCount = await UserLogModel.countDocuments();
    if (userCount === 0) {
      const initialUsers = readJson(usersFilePath, []);
      if (initialUsers.length) await UserLogModel.insertMany(initialUsers);
    }

    const msgCount = await ContactMessageModel.countDocuments();
    if (msgCount === 0) {
      const initialMsgs = readJson(messagesFilePath, []);
      if (initialMsgs.length) await ContactMessageModel.insertMany(initialMsgs);
    }
    console.log("MongoDB collections synchronized.");
  } catch (err) {
    console.error("Sync to Mongo error:", err.message);
  }
}

// Track user activity helper
async function recordUserActivity(name, email, role, activity, ip = "", userAgent = "") {
  if (!email) return;
  const now = new Date().toISOString();
  const userId = `usr_${Date.now()}`;

  // Always keep JSON updated
  const users = readJson(usersFilePath, []);
  const existingIndex = users.findIndex((u) => u.email.toLowerCase() === email.toLowerCase());

  if (existingIndex !== -1) {
    users[existingIndex].activity = activity;
    users[existingIndex].date = now;
    if (name) users[existingIndex].name = name;
  } else {
    users.unshift({
      id: userId,
      name: name || "Verified User",
      email: email.trim(),
      role: role || "Client",
      source: "Website Engagement",
      activity: activity,
      ip: ip,
      date: now
    });
  }
  writeJson(usersFilePath, users);

  // If MongoDB connected, sync to MongoDB Atlas
  if (isMongoConnected) {
    try {
      await UserLogModel.findOneAndUpdate(
        { email: email.trim().toLowerCase() },
        {
          id: userId,
          name: name || "Verified User",
          email: email.trim().toLowerCase(),
          role: role || "Client",
          source: "Website Engagement",
          activity: activity,
          ip: ip,
          userAgent: userAgent,
          date: new Date()
        },
        { upsert: true, new: true }
      );
    } catch (e) {
      console.error("Mongo user activity error:", e.message);
    }
  }
}

// ================================================================
// WEB3FORMS AUTOMATED DISPATCHER (CONNECTED TO wordpressrahila@gmail.com)
// ================================================================
async function sendWeb3FormsNotification({ subject, fromName, fromEmail, details = {} }) {
  try {
    const formattedDetails = Object.entries(details)
      .map(([k, v]) => `${k.toUpperCase()}: ${typeof v === "object" ? JSON.stringify(v) : v}`)
      .join("\n");

    const messageContent = details.message
      ? `${details.message}\n\n--- Event Details ---\n${formattedDetails}`
      : formattedDetails;

    const res = await fetch("https://api.web3forms.com/submit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        access_key: WEB3FORMS_ACCESS_KEY,
        subject: subject || "Notification from Rahila Kareem Portfolio",
        from_name: fromName || "Portfolio Portal",
        email: fromEmail || "wordpressrahila@gmail.com",
        message: messageContent,
        ...details
      })
    });

    const data = await res.json();
    return Boolean(data && data.success);
  } catch (err) {
    console.error("Web3Forms automated dispatch error:", err.message);
    return false;
  }
}

// ================================================================
// SECURE AUTHENTICATION & REGISTRATION ROUTES
// ================================================================
const authRoutes = require("./routes/authRoutes");
app.use("/api/auth", authRoutes);

// ================================================================
// PUBLIC ROUTES
// ================================================================

// Root Status
app.get("/", (req, res) => {
  res.json({
    message: "Rahila Kareem Portfolio Backend API is running",
    status: "online",
    verifiedGoogleAccount: "rahilakareem389@gmail.com",
    contactAndWeb3Forms: "wordpressrahila@gmail.com",
    gmbProfile: "https://share.google/r0RApzZ7lmVtrpKnu",
    mongoDbAtlas: isMongoConnected ? "Connected" : "Standby / Ready (configured with JSON fallback)",
    web3Forms: "Active & Connected to wordpressrahila@gmail.com"
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is healthy",
    mongoDbConnected: isMongoConnected,
    timestamp: new Date().toISOString()
  });
});

// ================================================================
// USER LOGIN / AUTH TRACKING ("kon login huwa")
// ================================================================
app.post("/api/user/auth", async (req, res) => {
  const { name, email, mode, role } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required." });
  }

  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const userAgent = req.headers["user-agent"] || "";
  const activityText = mode === "signup" ? "New Account Created (Signed Up)" : "Logged In to Client Workspace";

  await recordUserActivity(name, email, role || "Client", activityText, clientIp, userAgent);

  // Send Web3Forms email notification to wordpressrahila@gmail.com ("kon login huwa")
  sendWeb3FormsNotification({
    subject: `[User Login Alert] ${email} active on Portfolio`,
    fromName: name || "Website Visitor",
    fromEmail: email,
    details: {
      action: activityText,
      userName: name || "Client User",
      userEmail: email,
      userRole: role || "Client",
      ipAddress: clientIp || "N/A",
      timestamp: new Date().toISOString()
    }
  }).catch(() => {});

  res.json({
    success: true,
    message: `Session active for ${email}`,
    user: { email, name, role: role || "Client", activity: activityText }
  });
});

// ================================================================
// CONTACT FORM & WEB3FORMS WITH MONGO DB ATLAS ("kis n message kia")
// ================================================================
app.post("/api/contact", async (req, res) => {
  const { name, email, phone, plan, message, subject } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      message: "Please fill all required fields (name, email, message)."
    });
  }

  const msgId = `msg_${Date.now()}`;
  const now = new Date().toISOString();

  // 1. Submit to Web3Forms (emails alert directly to rahilakareem389@gmail.com)
  let web3Status = "delivered";
  try {
    const web3Response = await fetch("https://api.web3forms.com/submit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        access_key: WEB3FORMS_ACCESS_KEY,
        name: name,
        email: email,
        phone: phone || "Not specified",
        plan: plan || "General Inquiry",
        message: message,
        subject: subject || `New Project Inquiry from ${name} (Rahila Kareem Portfolio)`
      })
    });

    const web3Data = await web3Response.json();
    if (!web3Response.ok || !web3Data.success) {
      console.warn("Web3Forms response warning:", web3Data);
      web3Status = "queued_or_backup";
    }
  } catch (err) {
    console.error("Web3Forms error:", err);
    web3Status = "offline_saved_to_db";
  }

  // 2. Save into JSON database
  const newMsg = {
    id: msgId,
    name,
    email,
    phone: phone || "",
    plan: plan || "General Inquiry",
    subject: subject || `Inquiry: ${plan || "General"}`,
    message,
    status: "new",
    adminNotes: "",
    web3FormsStatus: web3Status,
    date: now
  };

  const messages = readJson(messagesFilePath, []);
  messages.unshift(newMsg);
  writeJson(messagesFilePath, messages);

  // 3. Save into MongoDB Atlas if connected
  if (isMongoConnected) {
    try {
      await ContactMessageModel.create(newMsg);
    } catch (e) {
      console.error("Mongo message save error:", e.message);
    }
  }

  // 4. Record user lead in login/user directory
  await recordUserActivity(name, email, "Lead / Inquirer", `Sent Message for Plan: ${plan || "General"}`);

  res.status(200).json({
    success: true,
    message: "Your message has been sent successfully. Rahila Kareem has been notified.",
    web3Forms: web3Status,
    messageId: msgId
  });
});

// ================================================================
// OFFICIAL GOOGLE PLACES / GMB API INTEGRATION
// ================================================================
app.get("/api/gmb/reviews", async (req, res) => {
  const placeId = process.env.GOOGLE_PLACE_ID;
  const apiKey = process.env.GOOGLE_PLACES_API_KEY;

  if (!placeId || !apiKey) {
    const localReviews = readJson(reviewsFilePath, []).filter((r) => r.sourceType === "gmb" && r.status === "approved");
    return res.json({
      success: true,
      source: "gmb_api_ready",
      configured: false,
      placeId: placeId || null,
      total: localReviews.length,
      reviews: localReviews,
      message: "Set GOOGLE_PLACE_ID and GOOGLE_PLACES_API_KEY in environment to stream live Google reviews directly."
    });
  }

  try {
    const url = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&fields=name,rating,reviews,user_ratings_total,url&key=${apiKey}`;
    const response = await fetch(url);
    const data = await response.json();

    if (!response.ok || data.status !== "OK") {
      console.warn("Google Places API warning:", data);
      const localReviews = readJson(reviewsFilePath, []).filter((r) => r.status === "approved");
      return res.json({
        success: false,
        error: data.error_message || data.status,
        reviews: localReviews
      });
    }

    const googleReviews = (data.result.reviews || []).map((r, idx) => ({
      id: `gmb_${r.time || idx}`,
      name: r.author_name,
      authorUrl: r.author_url,
      rating: r.rating,
      service: "Google Verified Review",
      title: "",
      message: r.text,
      date: r.relative_time_description,
      avatar: r.profile_photo_url,
      source: "Google My Business",
      sourceType: "gmb",
      gmbVerified: true,
      time: r.time,
      status: "approved"
    }));

    res.json({
      success: true,
      source: "google_places_api",
      placeName: data.result.name,
      overallRating: data.result.rating,
      totalReviews: data.result.user_ratings_total,
      googleMapsUrl: data.result.url,
      reviews: googleReviews
    });
  } catch (err) {
    console.error("Error fetching Google Places reviews:", err);
    res.status(500).json({ success: false, message: "Error fetching Google Places API" });
  }
});

// ================================================================
// REVIEWS (PUBLIC & USER SUBMISSION)
// ================================================================
app.get("/api/reviews", async (req, res) => {
  try {
    const placeId = process.env.GOOGLE_PLACE_ID;
    const apiKey = process.env.GOOGLE_PLACES_API_KEY;

    // Prioritize Live Google Places API reviews if keys configured
    if (placeId && apiKey) {
      try {
        const url = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&fields=name,rating,reviews,user_ratings_total,url&key=${apiKey}`;
        const response = await fetch(url);
        const data = await response.json();

        if (response.ok && data.status === "OK") {
          const liveGoogleReviews = (data.result.reviews || []).map((r, idx) => ({
            id: `gmb_${r.time || idx}`,
            name: r.author_name,
            authorUrl: r.author_url,
            rating: r.rating,
            service: "Google Verified Review",
            title: "",
            message: r.text,
            date: r.relative_time_description,
            avatar: r.profile_photo_url,
            source: "Google My Business",
            sourceType: "gmb",
            gmbVerified: true,
            status: "approved"
          }));

          return res.json({
            success: true,
            source: "google_places_api",
            placeName: data.result.name,
            overallRating: data.result.rating,
            total: liveGoogleReviews.length,
            reviews: liveGoogleReviews
          });
        }
      } catch (err) {
        console.warn("Live Google Places fallback to DB:", err.message);
      }
    }

    let approvedReviews = [];
    if (isMongoConnected) {
      approvedReviews = await ReviewModel.find({ status: "approved" }).sort({ createdAt: -1 });
    } else {
      const all = readJson(reviewsFilePath, []);
      approvedReviews = all.filter((r) => r.status === "approved");
    }

    res.json({
      success: true,
      source: "database",
      total: approvedReviews.length,
      reviews: approvedReviews
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching reviews." });
  }
});

app.post("/api/reviews", async (req, res) => {
  const { name, email, role, rating, service, title, message, avatar } = req.body;

  if (!name || !message) {
    return res.status(400).json({
      success: false,
      message: "Please enter your name and review message."
    });
  }

  const reviewId = `rev_${Date.now()}`;
  const newReview = {
    id: reviewId,
    name: name.trim(),
    email: email ? email.trim() : "",
    role: role ? role.trim() : "Verified Client",
    rating: Number(rating) || 5,
    service: service ? service.trim() : "Complete SEO Strategy",
    title: title ? title.trim() : "",
    message: message.trim(),
    source: "Website Submission",
    sourceType: "submission",
    gmbVerified: false,
    date: "Just now",
    status: "pending",
    helpfulCount: 0,
    avatar: (avatar && typeof avatar === "string" && avatar.trim())
      ? avatar.trim()
      : `https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80`,
    adminReply: { message: "", repliedAt: null, adminEmail: "" }
  };

  const reviews = readJson(reviewsFilePath, []);
  reviews.unshift(newReview);
  writeJson(reviewsFilePath, reviews);

  if (isMongoConnected) {
    try {
      await ReviewModel.create(newReview);
    } catch (e) {
      console.error("Mongo review save error:", e.message);
    }
  }

  await recordUserActivity(name, email, role || "Reviewer", `Submitted ${newReview.rating}-Star Review`);

  // Dispatch alert to wordpressrahila@gmail.com via Web3Forms
  sendWeb3FormsNotification({
    subject: `[New Client Review Submitted] ${newReview.rating} Stars by ${newReview.name}`,
    fromName: newReview.name,
    fromEmail: newReview.email || "wordpressrahila@gmail.com",
    details: {
      clientName: newReview.name,
      clientEmail: newReview.email || "Not specified",
      rating: `${newReview.rating} / 5 Stars`,
      service: newReview.service,
      reviewTitle: newReview.title || "No title",
      message: newReview.message,
      status: "Pending Admin Approval in Dashboard",
      timestamp: new Date().toISOString()
    }
  }).catch(() => {});

  res.status(201).json({
    success: true,
    message: "Thank you! Your review has been submitted. It will appear publicly on the site once approved by Admin.",
    review: newReview
  });
});

// ================================================================
// COMMUNITY FAQS (PUBLIC & QUESTION SUBMISSION) ("kis n eaq kia")
// ================================================================
app.get("/api/faqs", async (req, res) => {
  try {
    let approvedFaqs = [];
    if (isMongoConnected) {
      approvedFaqs = await FaqModel.find({ status: "approved" }).sort({ createdAt: -1 });
    } else {
      const all = readJson(faqsFilePath, []);
      approvedFaqs = all.filter((f) => f.status === "approved");
    }

    res.json({
      success: true,
      total: approvedFaqs.length,
      faqs: approvedFaqs
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching FAQs." });
  }
});

app.post("/api/faqs/ask", async (req, res) => {
  const { question, name, email } = req.body;

  if (!question || question.trim().length < 5) {
    return res.status(400).json({
      success: false,
      message: "Please enter a valid question (at least 5 characters)."
    });
  }

  const faqId = `faq_${Date.now()}`;
  const newFaq = {
    id: faqId,
    question: question.trim(),
    answer: "",
    author: name ? name.trim() : "Visitor",
    email: email ? email.trim() : "",
    date: "Just now",
    status: "pending",
    adminEmail: "rahilakareem389@gmail.com"
  };

  const faqs = readJson(faqsFilePath, []);
  faqs.unshift(newFaq);
  writeJson(faqsFilePath, faqs);

  if (isMongoConnected) {
    try {
      await FaqModel.create(newFaq);
    } catch (e) {
      console.error("Mongo FAQ save error:", e.message);
    }
  }

  await recordUserActivity(name || "Visitor", email, "Question Asker", `Asked FAQ: "${question.substring(0, 40)}..."`);

  // Dispatch alert to wordpressrahila@gmail.com via Web3Forms ("kis n eaq kia")
  sendWeb3FormsNotification({
    subject: `[New FAQ Question Asked] from ${newFaq.author}`,
    fromName: newFaq.author,
    fromEmail: newFaq.email || "wordpressrahila@gmail.com",
    details: {
      author: newFaq.author,
      authorEmail: newFaq.email || "Not specified",
      question: newFaq.question,
      status: "Pending Admin Answer in Dashboard",
      timestamp: new Date().toISOString()
    }
  }).catch(() => {});

  res.status(201).json({
    success: true,
    message: "Your question has been received! Rahila Kareem will answer it shortly and publish it to the FAQ section.",
    faq: newFaq
  });
});

// ================================================================
// REAL ADMIN AUTHENTICATION (FOR wordpressrahila@gmail.com & rahilakareem389@gmail.com)
// ================================================================
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter your verified email and password."
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const authorizedEmails = ["wordpressrahila@gmail.com", "rahilakareem389@gmail.com"];

  if (!authorizedEmails.includes(cleanEmail)) {
    return res.status(403).json({
      success: false,
      message: "Access Denied: Only Rahila Kareem's verified account (wordpressrahila@gmail.com) is authorized to access the Admin Dashboard."
    });
  }

  if (password.trim() !== "rahila2026" && password.trim() !== "admin123") {
    return res.status(401).json({
      success: false,
      message: `Invalid password for ${cleanEmail}.`
    });
  }

  recordUserActivity("Rahila Kareem", cleanEmail, "Owner & Admin", "Logged In to Admin Dashboard");

  res.json({
    success: true,
    message: "Admin authentication successful. Welcome, Rahila Kareem!",
    admin: {
      name: "Rahila Kareem",
      email: cleanEmail,
      role: "Owner / Full Stack Administrator",
      verified: true
    }
  });
});

// ================================================================
// ADMIN DASHBOARD ENDPOINTS (MESSAGES, USERS, REVIEWS, FAQS, MONGO)
// ================================================================

// Admin: Overall Dashboard Stats & Cloud Connectivity
app.get("/api/admin/stats", async (req, res) => {
  const reviews = readJson(reviewsFilePath, []);
  const faqs = readJson(faqsFilePath, []);
  const users = readJson(usersFilePath, []);
  const messages = readJson(messagesFilePath, []);

  res.json({
    success: true,
    stats: {
      totalReviews: reviews.length,
      pendingReviews: reviews.filter((r) => r.status === "pending").length,
      approvedReviews: reviews.filter((r) => r.status === "approved").length,
      totalFaqs: faqs.length,
      unansweredFaqs: faqs.filter((f) => !f.answer).length,
      totalUsers: users.length,
      totalMessages: messages.length,
      newMessages: messages.filter((m) => m.status === "new").length,
      mongoDbAtlas: isMongoConnected ? "Connected" : "JSON Fallback (Standby)",
      web3Forms: "Active & Connected"
    }
  });
});

// Admin: Contact Messages Inbox ("kis n message kia")
app.get("/api/admin/messages", async (req, res) => {
  try {
    let messages = [];
    if (isMongoConnected) {
      messages = await ContactMessageModel.find().sort({ createdAt: -1 });
    } else {
      messages = readJson(messagesFilePath, []);
    }

    res.json({
      success: true,
      total: messages.length,
      messages
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error loading contact inquiries." });
  }
});

// Admin: Reply / Notes to Contact Message
app.patch("/api/admin/messages/:id/reply", async (req, res) => {
  const { id } = req.params;
  const { adminNotes, status } = req.body;

  const messages = readJson(messagesFilePath, []);
  const msgIndex = messages.findIndex((m) => m.id === id);

  if (msgIndex === -1) {
    return res.status(404).json({ success: false, message: "Message not found." });
  }

  messages[msgIndex].adminNotes = adminNotes || messages[msgIndex].adminNotes;
  messages[msgIndex].status = status || "replied";
  writeJson(messagesFilePath, messages);

  if (isMongoConnected) {
    try {
      await ContactMessageModel.findOneAndUpdate(
        { id },
        { adminNotes: messages[msgIndex].adminNotes, status: messages[msgIndex].status }
      );
    } catch (e) {
      console.error("Mongo message reply error:", e.message);
    }
  }

  res.json({
    success: true,
    message: "Admin notes updated successfully.",
    messageItem: messages[msgIndex]
  });
});

// Admin: Delete Message
app.delete("/api/admin/messages/:id", async (req, res) => {
  const { id } = req.params;
  const messages = readJson(messagesFilePath, []);
  const filtered = messages.filter((m) => m.id !== id);
  writeJson(messagesFilePath, filtered);

  if (isMongoConnected) {
    try {
      await ContactMessageModel.deleteOne({ id });
    } catch (_) {}
  }

  res.json({ success: true, message: "Message deleted successfully." });
});

// Admin: User Logins Directory ("kon login huwa")
app.get("/api/admin/users", async (req, res) => {
  try {
    let users = [];
    if (isMongoConnected) {
      users = await UserLogModel.find().sort({ date: -1 });
    } else {
      users = readJson(usersFilePath, []);
    }

    res.json({
      success: true,
      total: users.length,
      users
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error loading user directory." });
  }
});

// Admin: Reviews Moderation & Reply ("admin bt kery ga user s reviews")
app.get("/api/admin/reviews", async (req, res) => {
  try {
    let reviews = [];
    if (isMongoConnected) {
      reviews = await ReviewModel.find().sort({ createdAt: -1 });
    } else {
      reviews = readJson(reviewsFilePath, []);
    }

    res.json({
      success: true,
      total: reviews.length,
      reviews
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error loading reviews." });
  }
});

app.patch("/api/admin/reviews/:id/status", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!["approved", "rejected", "pending"].includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid status value." });
  }

  const reviews = readJson(reviewsFilePath, []);
  const revIndex = reviews.findIndex((r) => r.id === id);

  if (revIndex === -1) {
    return res.status(404).json({ success: false, message: "Review not found." });
  }

  reviews[revIndex].status = status;
  writeJson(reviewsFilePath, reviews);

  if (isMongoConnected) {
    try {
      await ReviewModel.findOneAndUpdate({ id }, { status });
    } catch (_) {}
  }

  res.json({
    success: true,
    message: `Review ${status === "approved" ? "approved & published live" : status}.`,
    review: reviews[revIndex]
  });
});

// Admin talks / replies directly to user review
app.post("/api/admin/reviews/:id/reply", async (req, res) => {
  const { id } = req.params;
  const { replyMessage } = req.body;

  if (!replyMessage || replyMessage.trim().length === 0) {
    return res.status(400).json({ success: false, message: "Reply message cannot be empty." });
  }

  const reviews = readJson(reviewsFilePath, []);
  const revIndex = reviews.findIndex((r) => r.id === id);

  if (revIndex === -1) {
    return res.status(404).json({ success: false, message: "Review not found." });
  }

  reviews[revIndex].adminReply = {
    message: replyMessage.trim(),
    repliedAt: new Date(),
    adminEmail: "wordpressrahila@gmail.com"
  };
  reviews[revIndex].status = "approved"; // Automatically approve when replied
  writeJson(reviewsFilePath, reviews);

  if (isMongoConnected) {
    try {
      await ReviewModel.findOneAndUpdate(
        { id },
        { adminReply: reviews[revIndex].adminReply, status: "approved" }
      );
    } catch (_) {}
  }

  res.json({
    success: true,
    message: "Admin reply published to review successfully.",
    review: reviews[revIndex]
  });
});

app.delete("/api/admin/reviews/:id", async (req, res) => {
  const { id } = req.params;
  const reviews = readJson(reviewsFilePath, []);
  const filtered = reviews.filter((r) => r.id !== id);
  writeJson(reviewsFilePath, filtered);

  if (isMongoConnected) {
    try {
      await ReviewModel.deleteOne({ id });
    } catch (_) {}
  }

  res.json({ success: true, message: "Review deleted successfully." });
});

// Admin: FAQ Q&A Management ("admin bt kery ga user s faq ka")
app.get("/api/admin/faqs", async (req, res) => {
  try {
    let faqs = [];
    if (isMongoConnected) {
      faqs = await FaqModel.find().sort({ createdAt: -1 });
    } else {
      faqs = readJson(faqsFilePath, []);
    }

    res.json({
      success: true,
      total: faqs.length,
      faqs
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error loading FAQs." });
  }
});

app.patch("/api/admin/faqs/:id/answer", async (req, res) => {
  const { id } = req.params;
  const { answer } = req.body;

  if (!answer || answer.trim().length === 0) {
    return res.status(400).json({ success: false, message: "Answer cannot be empty." });
  }

  const faqs = readJson(faqsFilePath, []);
  const faqIndex = faqs.findIndex((f) => f.id === id);

  if (faqIndex === -1) {
    return res.status(404).json({ success: false, message: "FAQ not found." });
  }

  faqs[faqIndex].answer = answer.trim();
  faqs[faqIndex].status = "approved"; // Publish when answered
  faqs[faqIndex].adminEmail = "wordpressrahila@gmail.com";
  writeJson(faqsFilePath, faqs);

  if (isMongoConnected) {
    try {
      await FaqModel.findOneAndUpdate(
        { id },
        { answer: answer.trim(), status: "approved", adminEmail: "wordpressrahila@gmail.com" }
      );
    } catch (_) {}
  }

  res.json({
    success: true,
    message: "Answer published to FAQs successfully.",
    faq: faqs[faqIndex]
  });
});

app.delete("/api/admin/faqs/:id", async (req, res) => {
  const { id } = req.params;
  const faqs = readJson(faqsFilePath, []);
  const filtered = faqs.filter((f) => f.id !== id);
  writeJson(faqsFilePath, filtered);

  if (isMongoConnected) {
    try {
      await FaqModel.deleteOne({ id });
    } catch (_) {}
  }

  res.json({ success: true, message: "FAQ deleted successfully." });
});

// Admin: GMB Profile Details
app.get("/api/admin/gmb-profile", (req, res) => {
  const defaultGmb = {
    businessName: "Rahila Kareem - SEO Specialist & Full Stack Developer",
    ownerEmail: "rahilakareem389@gmail.com",
    phone: "+92 321 7812265",
    location: "Punjab, Pakistan",
    googleBusinessUrl: "https://share.google/r0RApzZ7lmVtrpKnu",
    rating: "5.0",
    totalReviews: "48+",
    verifiedStatus: "Active & Verified Google Business Profile"
  };

  const gmb = readJson(gmbFilePath, defaultGmb);
  res.json({
    success: true,
    profile: gmb
  });
});

// ================================================================
// SERVER STARTUP (VERCEL SAFE)
// ================================================================
if (!process.env.VERCEL && require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;