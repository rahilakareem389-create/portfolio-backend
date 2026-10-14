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

// Reviews file path
const reviewsFilePath = path.join(__dirname, "data", "reviews.json");

// Helper to read reviews
function getReviews() {
  try {
    if (!fs.existsSync(reviewsFilePath)) {
      return [];
    }
    const data = fs.readFileSync(reviewsFilePath, "utf8");
    return JSON.parse(data || "[]");
  } catch (err) {
    console.error("Error reading reviews.json:", err);
    return [];
  }
}

// Helper to save reviews
function saveReviews(reviews) {
  try {
    const dir = path.dirname(reviewsFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(reviewsFilePath, JSON.stringify(reviews, null, 2), "utf8");
    return true;
  } catch (err) {
    console.error("Error saving reviews.json:", err);
    return false;
  }
}

// Root Route
app.get("/", (req, res) => {
  res.json({
    message: "Rahila Kareem Portfolio Backend API is running on Render",
    status: "online",
    endpoints: {
      health: "/api/health",
      contact: "POST /api/contact",
      reviews: "GET & POST /api/reviews",
      adminReviews: "GET & PATCH & DELETE /api/admin/reviews"
    }
  });
});

// Health check for Render
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is healthy and ready on Render",
    timestamp: new Date().toISOString()
  });
});

// Contact form via Web3Forms
app.post("/api/contact", async (req, res) => {
  const { name, email, message, subject } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      message: "Please fill all required fields (name, email, message)."
    });
  }

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

// ================================================================
// REVIEWS & TESTIMONIALS API
// ================================================================

// Public: Get all APPROVED reviews (GMB & Verified Client Testimonials)
app.get("/api/reviews", (req, res) => {
  const reviews = getReviews();
  const approvedReviews = reviews.filter((r) => r.status === "approved");
  res.json({
    success: true,
    total: approvedReviews.length,
    reviews: approvedReviews
  });
});

// Public: Submit a new review (Saved as 'pending' until approved by Admin)
app.post("/api/reviews", (req, res) => {
  const { name, email, role, service, rating, title, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      message: "Please provide your name, email, and review message."
    });
  }

  const reviews = getReviews();
  const newReview = {
    id: `rev_${Date.now()}`,
    name: name.trim(),
    email: email.trim(),
    role: (role || "Verified Client").trim(),
    rating: Number(rating) || 5,
    service: (service || "General Consultation").trim(),
    title: (title || "Great Experience & Results").trim(),
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
  saveReviews(reviews);

  res.status(201).json({
    success: true,
    message: "Thank you! Your review has been submitted. It will appear on the site once approved by Admin.",
    review: newReview
  });
});

// Admin: Get ALL reviews (pending, approved, rejected)
app.get("/api/admin/reviews", (req, res) => {
  const reviews = getReviews();
  const pendingCount = reviews.filter((r) => r.status === "pending").length;
  const approvedCount = reviews.filter((r) => r.status === "approved").length;
  const rejectedCount = reviews.filter((r) => r.status === "rejected").length;

  res.json({
    success: true,
    stats: {
      total: reviews.length,
      pending: pendingCount,
      approved: approvedCount,
      rejected: rejectedCount
    },
    reviews
  });
});

// Admin: Update review status (Accept/Approve or Reject)
app.patch("/api/admin/reviews/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!["approved", "rejected", "pending"].includes(status)) {
    return res.status(400).json({
      success: false,
      message: "Invalid status. Allowed values: approved, rejected, pending."
    });
  }

  const reviews = getReviews();
  const index = reviews.findIndex((r) => r.id === id);

  if (index === -1) {
    return res.status(404).json({
      success: false,
      message: "Review not found."
    });
  }

  reviews[index].status = status;
  reviews[index].updatedAt = new Date().toISOString();
  saveReviews(reviews);

  res.json({
    success: true,
    message: `Review status successfully updated to '${status}'.`,
    review: reviews[index]
  });
});

// Admin: Delete review permanently
app.delete("/api/admin/reviews/:id", (req, res) => {
  const { id } = req.params;
  const reviews = getReviews();
  const filtered = reviews.filter((r) => r.id !== id);

  if (filtered.length === reviews.length) {
    return res.status(404).json({
      success: false,
      message: "Review not found."
    });
  }

  saveReviews(filtered);

  res.json({
    success: true,
    message: "Review deleted successfully."
  });
});

// Admin: Manually add a review
app.post("/api/admin/reviews", (req, res) => {
  const { name, email, role, service, rating, title, message, source, sourceType, gmbVerified, status } = req.body;

  if (!name || !message) {
    return res.status(400).json({
      success: false,
      message: "Name and message are required."
    });
  }

  const reviews = getReviews();
  const newReview = {
    id: `rev_${Date.now()}`,
    name: name.trim(),
    email: (email || "").trim(),
    role: (role || "Verified Client").trim(),
    rating: Number(rating) || 5,
    service: (service || "SEO & Web Development").trim(),
    title: (title || "Excellent Service").trim(),
    message: message.trim(),
    source: source || "Google My Business",
    sourceType: sourceType || "gmb",
    gmbVerified: gmbVerified !== undefined ? Boolean(gmbVerified) : true,
    date: "Just now",
    status: status || "approved",
    helpfulCount: 0,
    createdAt: new Date().toISOString()
  };

  reviews.unshift(newReview);
  saveReviews(reviews);

  res.status(201).json({
    success: true,
    message: "Review added successfully.",
    review: newReview
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});