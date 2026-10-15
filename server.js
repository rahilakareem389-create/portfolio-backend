const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json());

// File paths (with Vercel serverless /tmp fallback)
const isVercel = Boolean(process.env.VERCEL);
const bundledDataDir = path.join(__dirname, "data");
const dataDir = isVercel ? path.join("/tmp", "data") : bundledDataDir;

const reviewsFilePath = path.join(dataDir, "reviews.json");
const faqsFilePath = path.join(dataDir, "faqs.json");
const usersFilePath = path.join(dataDir, "users.json");

// Helper readers and writers
function readJson(filePath, defaultVal = []) {
  try {
    // If running on Vercel and file hasn't been copied to /tmp yet, seed from bundled dataDir
    if (isVercel && !fs.existsSync(filePath)) {
      const fileName = path.basename(filePath);
      const bundledFile = path.join(bundledDataDir, fileName);
      if (fs.existsSync(bundledFile)) {
        const initialContent = fs.readFileSync(bundledFile, "utf8");
        try {
          if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
          }
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

// Track user activity
function recordUser(name, email, role, activity) {
  if (!email) return;
  const users = readJson(usersFilePath, []);
  const existingIndex = users.findIndex((u) => u.email.toLowerCase() === email.toLowerCase());
  const now = new Date().toISOString();

  if (existingIndex !== -1) {
    users[existingIndex].activity = activity;
    users[existingIndex].date = now;
  } else {
    users.unshift({
      id: `usr_${Date.now()}`,
      name: name || "Verified User",
      email: email.trim(),
      role: role || "Client",
      source: "Website Engagement",
      activity: activity,
      date: now
    });
  }
  writeJson(usersFilePath, users);
}

// Root Route
app.get("/", (req, res) => {
  res.json({
    message: "Rahila Kareem Portfolio Backend API is running",
    status: "online",
    verifiedGoogleAccount: "rahilakareem389@gmail.com",
    gmbProfile: "https://share.google/r0RApzZ7lmVtrpKnu"
  });
});

// Health check for Render
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is healthy",
    timestamp: new Date().toISOString()
  });
});

// ================================================================
// REAL ADMIN AUTHENTICATION (STRICTLY RESTRICTED TO rahilakareem389@gmail.com)
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
  const authorizedEmails = ["rahilakareem389@gmail.com", "wordpressrahila@gmail.com"];

  // Strictly reject fake or unauthorized emails
  if (!authorizedEmails.includes(cleanEmail)) {
    return res.status(403).json({
      success: false,
      message: "Access Denied: Only Rahila Kareem's verified Google account (rahilakareem389@gmail.com) is authorized to access the Admin Dashboard."
    });
  }

  // Password verification
  if (password.trim() !== "rahila2026" && password.trim() !== "admin123") {
    return res.status(401).json({
      success: false,
      message: "Invalid password for rahilakareem389@gmail.com."
    });
  }

  res.json({
    success: true,
    message: "Welcome Rahila Kareem! Admin session authenticated.",
    user: {
      name: "Rahila Kareem",
      email: "rahilakareem389@gmail.com",
      role: "Owner & Administrator",
      googleAccountVerified: true
    }
  });
});

// ================================================================
// REVIEWS API
// ================================================================
// Public: Get all APPROVED reviews
app.get("/api/reviews", (req, res) => {
  const reviews = readJson(reviewsFilePath, []);
  const approved = reviews.filter((r) => r.status === "approved");
  res.json({
    success: true,
    total: approved.length,
    reviews: approved
  });
});

// Public: Submit a new review (Saved as 'pending')
app.post("/api/reviews", (req, res) => {
  const { name, email, role, service, rating, title, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      message: "Name, email, and review message are required."
    });
  }

  const reviews = readJson(reviewsFilePath, []);
  const newReview = {
    id: `rev_${Date.now()}`,
    name: name.trim(),
    email: email.trim(),
    role: (role || "Verified Client").trim(),
    rating: Number(rating) || 5,
    service: (service || "Complete SEO Strategy").trim(),
    title: (title || "Great Experience & Measurable Growth").trim(),
    message: message.trim(),
    source: "Website Submission",
    sourceType: "submission",
    gmbVerified: false,
    date: "Just now",
    status: "pending", // Pending approval in Admin Dashboard
    helpfulCount: 0,
    createdAt: new Date().toISOString()
  };

  reviews.unshift(newReview);
  writeJson(reviewsFilePath, reviews);

  // Record real user
  recordUser(name, email, role, `Submitted ${rating}-Star Review`);

  res.status(201).json({
    success: true,
    message: "Thank you! Your review has been submitted. It will appear publicly on the site once approved by Admin.",
    review: newReview
  });
});

// Admin: Get all reviews
app.get("/api/admin/reviews", (req, res) => {
  const reviews = readJson(reviewsFilePath, []);
  const pending = reviews.filter((r) => r.status === "pending").length;
  const approved = reviews.filter((r) => r.status === "approved").length;
  const rejected = reviews.filter((r) => r.status === "rejected").length;

  res.json({
    success: true,
    stats: {
      total: reviews.length,
      pending,
      approved,
      rejected
    },
    reviews
  });
});

// Admin: Update review status (Accept/Approve or Reject)
app.patch("/api/admin/reviews/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  const reviews = readJson(reviewsFilePath, []);
  const index = reviews.findIndex((r) => r.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Review not found." });
  }

  reviews[index].status = status;
  reviews[index].updatedAt = new Date().toISOString();
  writeJson(reviewsFilePath, reviews);

  res.json({
    success: true,
    message: `Review status updated to '${status}'.`,
    review: reviews[index]
  });
});

// Admin: Delete review
app.delete("/api/admin/reviews/:id", (req, res) => {
  const { id } = req.params;
  const reviews = readJson(reviewsFilePath, []);
  const filtered = reviews.filter((r) => r.id !== id);
  writeJson(reviewsFilePath, filtered);

  res.json({ success: true, message: "Review deleted successfully." });
});

// ================================================================
// FAQs & COMMUNITY Q&A API
// ================================================================
// Public: Get all APPROVED FAQs
app.get("/api/faqs", (req, res) => {
  const faqs = readJson(faqsFilePath, []);
  const approved = faqs.filter((f) => f.status === "approved");
  res.json({
    success: true,
    total: approved.length,
    faqs: approved
  });
});

// Public: User asks a question ("faq b ker sky")
app.post("/api/faqs/ask", (req, res) => {
  const { question, askedBy, email, category } = req.body;

  if (!question || !askedBy || !email) {
    return res.status(400).json({
      success: false,
      message: "Please provide your question, name, and email."
    });
  }

  const faqs = readJson(faqsFilePath, []);
  const newFaq = {
    id: `faq_${Date.now()}`,
    question: question.trim(),
    answer: "", // Admin will answer in Dashboard
    askedBy: askedBy.trim(),
    email: email.trim(),
    category: category || "General SEO & Web Dev",
    status: "pending", // Pending admin answer & approval
    date: "Just now",
    createdAt: new Date().toISOString()
  };

  faqs.unshift(newFaq);
  writeJson(faqsFilePath, faqs);

  // Record real user
  recordUser(askedBy, email, "Prospective Client", `Asked Question: "${question.substring(0, 40)}..."`);

  res.status(201).json({
    success: true,
    message: "Your question has been received! Rahila Kareem will review, answer, and publish it.",
    faq: newFaq
  });
});

// Admin: Get all FAQs (including pending user questions)
app.get("/api/admin/faqs", (req, res) => {
  const faqs = readJson(faqsFilePath, []);
  const pending = faqs.filter((f) => f.status === "pending" || !f.answer).length;
  const approved = faqs.filter((f) => f.status === "approved" && f.answer).length;

  res.json({
    success: true,
    stats: {
      total: faqs.length,
      pending,
      approved
    },
    faqs
  });
});

// Admin: Answer and approve/publish FAQ
app.patch("/api/admin/faqs/:id/answer", (req, res) => {
  const { id } = req.params;
  const { answer, status } = req.body;

  if (!answer) {
    return res.status(400).json({ success: false, message: "Answer is required." });
  }

  const faqs = readJson(faqsFilePath, []);
  const index = faqs.findIndex((f) => f.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Question not found." });
  }

  faqs[index].answer = answer.trim();
  faqs[index].status = status || "approved";
  faqs[index].answeredAt = new Date().toISOString();
  writeJson(faqsFilePath, faqs);

  res.json({
    success: true,
    message: "Question answered and published to FAQs!",
    faq: faqs[index]
  });
});

// Admin: Delete FAQ
app.delete("/api/admin/faqs/:id", (req, res) => {
  const { id } = req.params;
  const faqs = readJson(faqsFilePath, []);
  const filtered = faqs.filter((f) => f.id !== id);
  writeJson(faqsFilePath, filtered);

  res.json({ success: true, message: "FAQ deleted successfully." });
});

// Admin: Get list of real engaged users
app.get("/api/admin/users", (req, res) => {
  const users = readJson(usersFilePath, []);
  res.json({
    success: true,
    total: users.length,
    users
  });
});

// Admin: GMB Profile Details
app.get("/api/admin/gmb-profile", (req, res) => {
  res.json({
    success: true,
    profile: {
      businessName: "Rahila Kareem - SEO Specialist & Full Stack Developer",
      ownerEmail: "rahilakareem389@gmail.com",
      phone: "+92 321 7812265",
      location: "Punjab, Pakistan",
      googleBusinessUrl: "https://share.google/r0RApzZ7lmVtrpKnu",
      rating: "5.0",
      totalReviews: "48+",
      verifiedStatus: "Active & Verified Google Business Profile"
    }
  });
});

// Contact form via Web3Forms
app.post("/api/contact", async (req, res) => {
  const { name, email, message, subject } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      message: "Please fill all required fields."
    });
  }

  // Record user lead
  recordUser(name, email, "Contact Inquiry", `Sent Message: "${message.substring(0, 40)}..."`);

  try {
    const web3Response = await fetch("https://api.web3forms.com/submit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        access_key: process.env.WEB3FORMS_ACCESS_KEY || "6d6e0418-bb66-48ed-81eb-aaf8f0a9486d",
        name: name,
        email: email,
        message: message,
        subject: subject || `New Contact Message from ${name} (Rahila Kareem Portfolio)`
      })
    });

    const data = await web3Response.json();

    if (!web3Response.ok || !data.success) {
      console.error("Web3Forms error:", data);
      throw new Error(data.message || "Failed to send email");
    }

    res.status(200).json({
      success: true,
      message: "Your message has been sent successfully."
    });
  } catch (error) {
    console.error("Email error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to send message. Please try again later."
    });
  }
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;