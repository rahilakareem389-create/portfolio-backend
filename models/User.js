const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlength: [80, "Name cannot exceed 80 characters"]
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
        "Please provide a valid email address"
      ],
      index: true
    },
    passwordHash: {
      type: String,
      required: [true, "Password is required"],
      select: false // Never return password hash in regular queries
    },
    role: {
      type: String,
      enum: ["Client", "Admin"],
      default: "Client"
    },
    isVerified: {
      type: Boolean,
      default: false
    },
    verificationOtpHash: {
      type: String,
      select: false
    },
    verificationOtpExpires: {
      type: Date,
      select: false
    },
    resetPasswordOtpHash: {
      type: String,
      select: false
    },
    resetPasswordOtpExpires: {
      type: Date,
      select: false
    },
    lastLogin: {
      type: Date
    }
  },
  {
    timestamps: true
  }
);

// Method to verify candidate password against bcrypt hash
UserSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.passwordHash) return false;
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

// Method to return safe user object (stripping sensitive properties)
UserSchema.methods.toSafeObject = function () {
  return {
    id: this._id || this.id,
    name: this.name,
    email: this.email,
    role: this.role,
    isVerified: this.isVerified,
    createdAt: this.createdAt,
    lastLogin: this.lastLogin
  };
};

module.exports = mongoose.models.User || mongoose.model("User", UserSchema);
