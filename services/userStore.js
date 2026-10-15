const mongoose = require("mongoose");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const User = require("../models/User");

const isVercel = Boolean(process.env.VERCEL);
const bundledDataDir = path.join(__dirname, "..", "data");
const dataDir = isVercel ? path.join("/tmp", "data") : bundledDataDir;
const accountsFilePath = path.join(dataDir, "accounts.json");

function readJsonAccounts() {
  try {
    if (!fs.existsSync(accountsFilePath)) return [];
    const data = fs.readFileSync(accountsFilePath, "utf8");
    return JSON.parse(data || "[]");
  } catch (_) {
    return [];
  }
}

function writeJsonAccounts(accounts) {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(accountsFilePath, JSON.stringify(accounts, null, 2), "utf8");
    return true;
  } catch (_) {
    return false;
  }
}

// Check if Mongoose connection is ready
function isMongoReady() {
  return mongoose.connection && mongoose.connection.readyState === 1;
}

// Find user by normalized email
async function findUserByEmail(email, selectSecrets = false) {
  const cleanEmail = email.trim().toLowerCase();

  if (isMongoReady()) {
    try {
      const query = User.findOne({ email: cleanEmail });
      if (selectSecrets) {
        query.select("+passwordHash +verificationOtpHash +verificationOtpExpires");
      }
      const user = await query.exec();
      return user;
    } catch (err) {
      console.warn("[UserStore] Mongo query fallback to JSON store:", err.message);
    }
  }

  // JSON fallback
  const accounts = readJsonAccounts();
  const acc = accounts.find((a) => a.email.toLowerCase() === cleanEmail);
  if (!acc) return null;

  return {
    ...acc,
    comparePassword: async function (candidatePassword) {
      return bcrypt.compare(candidatePassword, this.passwordHash);
    },
    save: async function () {
      const all = readJsonAccounts();
      const idx = all.findIndex((a) => a.email.toLowerCase() === cleanEmail);
      if (idx !== -1) {
        all[idx] = { ...this };
        delete all[idx].comparePassword;
        delete all[idx].save;
        delete all[idx].toSafeObject;
      }
      writeJsonAccounts(all);
      return this;
    },
    toSafeObject: function () {
      return {
        id: this.id || this._id,
        name: this.name,
        email: this.email,
        role: this.role || "Client",
        isVerified: this.isVerified,
        createdAt: this.createdAt,
        lastLogin: this.lastLogin
      };
    }
  };
}

// Find user by ID
async function findUserById(id) {
  if (isMongoReady()) {
    try {
      return await User.findById(id);
    } catch (_) {}
  }

  const accounts = readJsonAccounts();
  const acc = accounts.find((a) => (a.id || a._id) === id);
  if (!acc) return null;

  return {
    ...acc,
    toSafeObject: function () {
      return {
        id: this.id || this._id,
        name: this.name,
        email: this.email,
        role: this.role || "Client",
        isVerified: this.isVerified,
        createdAt: this.createdAt,
        lastLogin: this.lastLogin
      };
    }
  };
}

// Create new user record
async function createUser(userData) {
  const cleanEmail = userData.email.trim().toLowerCase();

  if (isMongoReady()) {
    try {
      return await User.create({
        ...userData,
        email: cleanEmail
      });
    } catch (err) {
      if (err.code === 11000) throw err;
      console.warn("[UserStore] Mongo create fallback to JSON:", err.message);
    }
  }

  const accounts = readJsonAccounts();
  const exists = accounts.find((a) => a.email.toLowerCase() === cleanEmail);
  if (exists && exists.isVerified) {
    const duplicateError = new Error("Duplicate email");
    duplicateError.code = 11000;
    throw duplicateError;
  }

  const newUser = {
    id: `usr_${Date.now()}`,
    name: userData.name,
    email: cleanEmail,
    passwordHash: userData.passwordHash || "",
    role: userData.role || "Client",
    isVerified: Boolean(userData.isVerified),
    authProvider: userData.authProvider || "local",
    avatar: userData.avatar || "",
    googleId: userData.googleId || "",
    verificationOtpHash: userData.verificationOtpHash,
    verificationOtpExpires: userData.verificationOtpExpires,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  accounts.unshift(newUser);
  writeJsonAccounts(accounts);

  return {
    ...newUser,
    comparePassword: async function (candidatePassword) {
      if (!this.passwordHash) return false;
      return bcrypt.compare(candidatePassword, this.passwordHash);
    },
    save: async function () {
      const all = readJsonAccounts();
      const idx = all.findIndex((a) => a.email.toLowerCase() === cleanEmail);
      if (idx !== -1) {
        all[idx] = { ...this };
        delete all[idx].comparePassword;
        delete all[idx].save;
        delete all[idx].toSafeObject;
      }
      writeJsonAccounts(all);
      return this;
    },
    toSafeObject: function () {
      return {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isVerified: newUser.isVerified,
        authProvider: newUser.authProvider || "local",
        avatar: newUser.avatar || "",
        createdAt: newUser.createdAt
      };
    }
  };
}

// Delete user (e.g. For clean up in tests)
async function deleteUserByEmail(email) {
  const cleanEmail = email.trim().toLowerCase();
  if (isMongoReady()) {
    try {
      await User.deleteOne({ email: cleanEmail });
    } catch (_) {}
  }
  const accounts = readJsonAccounts();
  const filtered = accounts.filter((a) => a.email.toLowerCase() !== cleanEmail);
  writeJsonAccounts(filtered);
}

module.exports = {
  findUserByEmail,
  findUserById,
  createUser,
  deleteUserByEmail,
  isMongoReady
};
