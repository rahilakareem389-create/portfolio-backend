// Automated test suite for production authentication & email verification
const http = require("http");
const app = require("./server");
const { findUserByEmail, writeJsonAccounts, readJsonAccounts } = require("./services/userStore");
const { hashToken } = require("./services/emailService");

async function runTests() {
  console.log("\n=======================================================");
  console.log("🔒 STARTING PRODUCTION AUTHENTICATION & SECURITY TEST SUITE");
  console.log("=======================================================\n");

  const server = http.createServer(app);
  const TEST_PORT = 5098;
  await new Promise((resolve) => server.listen(TEST_PORT, resolve));
  const baseUrl = `http://localhost:${TEST_PORT}`;

  let testPassed = 0;
  let testTotal = 0;

  function assert(condition, testName, extraInfo = "") {
    testTotal++;
    if (condition) {
      testPassed++;
      console.log(`✅ [PASS] ${testName}`);
    } else {
      console.error(`❌ [FAIL] ${testName} ${extraInfo ? `-> ${extraInfo}` : ""}`);
    }
  }

  const testEmail = `test.client.${Date.now()}@example.com`;
  const strongPassword = "SecurePassword2026!";

  try {
    // -------------------------------------------------------------
    // Test 1: Reject invalid email format syntax
    // -------------------------------------------------------------
    const res1 = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Test User", email: "invalid-email-format", password: strongPassword })
    });
    const d1 = await res1.json();
    assert(res1.status === 400 && !d1.success, "1. Reject invalid email format syntax (status 400)");

    // -------------------------------------------------------------
    // Test 2: Reject weak password (missing symbols/digits/length)
    // -------------------------------------------------------------
    const res2 = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Test User", email: "weakpass@example.com", password: "weak" })
    });
    const d2 = await res2.json();
    assert(res2.status === 400 && d2.message.includes("Password must be at least 8"), "2. Reject weak password according to policy (status 400)");

    // -------------------------------------------------------------
    // Test 3: Valid registration creates unverified account with hashed password
    // -------------------------------------------------------------
    const res3 = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Rahila Client", email: testEmail, password: strongPassword })
    });
    const d3 = await res3.json();
    assert(res3.status === 201 && d3.success === true, "3. Valid registration creates unverified account (status 201)");

    // -------------------------------------------------------------
    // Test 4: Password is never stored in plaintext (must be bcrypt hash)
    // -------------------------------------------------------------
    const storedUser = await findUserByEmail(testEmail, true);
    const isBcrypt = storedUser && storedUser.passwordHash && (storedUser.passwordHash.startsWith("$2a$") || storedUser.passwordHash.startsWith("$2b$"));
    assert(isBcrypt, "4. Password is cryptographically hashed with bcrypt (never plaintext)");

    // -------------------------------------------------------------
    // Test 5: Single-use OTP token is stored as a 64-char SHA-256 hash
    // -------------------------------------------------------------
    const isSha256 = storedUser && storedUser.verificationOtpHash && storedUser.verificationOtpHash.length === 64;
    assert(isSha256, "5. Verification OTP is stored as a SHA-256 hash (never plaintext)");

    // -------------------------------------------------------------
    // Test 6: Block unverified account from logging in (Strict Verification Gate)
    // -------------------------------------------------------------
    const res6 = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, password: strongPassword })
    });
    const d6 = await res6.json();
    assert(res6.status === 403 && d6.code === "UNVERIFIED_EMAIL", "6. Block unverified account from logging in (403 UNVERIFIED_EMAIL)");

    // -------------------------------------------------------------
    // Test 7: Verify with incorrect OTP must fail (status 400)
    // -------------------------------------------------------------
    const res7 = await fetch(`${baseUrl}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, otp: "000000" })
    });
    const d7 = await res7.json();
    assert(res7.status === 400 && !d7.success, "7. Reject incorrect verification code (status 400)");

    // -------------------------------------------------------------
    // Test 8: Verify email ownership with valid OTP completes verification
    // -------------------------------------------------------------
    // Simulate setting known OTP hash for verification test
    const testOtp = "782941";
    storedUser.verificationOtpHash = hashToken(testOtp);
    storedUser.verificationOtpExpires = new Date(Date.now() + 15 * 60 * 1000);
    await storedUser.save();

    const res8 = await fetch(`${baseUrl}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, otp: testOtp })
    });
    const d8 = await res8.json();
    const verifiedJwtToken = d8.token;
    assert(res8.status === 200 && d8.success && verifiedJwtToken, "8. Valid OTP activates account and issues JWT session token");

    // -------------------------------------------------------------
    // Test 9: Single-use OTP is invalidated after activation
    // -------------------------------------------------------------
    const activatedUser = await findUserByEmail(testEmail, true);
    assert(activatedUser && activatedUser.isVerified === true && !activatedUser.verificationOtpHash, "9. Account marked isVerified=true and single-use OTP invalidated");

    // -------------------------------------------------------------
    // Test 10: Login succeeds after email verification
    // -------------------------------------------------------------
    const res10 = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, password: strongPassword })
    });
    const d10 = await res10.json();
    assert(res10.status === 200 && d10.success && d10.token, "10. Verified account successfully logs in and receives session token");

    // -------------------------------------------------------------
    // Test 11: Login rejects wrong password (status 401)
    // -------------------------------------------------------------
    const res11 = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, password: "WrongPassword999!" })
    });
    const d11 = await res11.json();
    assert(res11.status === 401 && !d11.success, "11. Login rejects incorrect password (status 401)");

    // -------------------------------------------------------------
    // Test 12: Duplicate registration for verified email is rejected (status 409)
    // -------------------------------------------------------------
    const res12 = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Duplicate Attempt", email: testEmail, password: strongPassword })
    });
    const d12 = await res12.json();
    assert(res12.status === 409, "12. Reject duplicate registration for already verified email (status 409)");

    // -------------------------------------------------------------
    // Test 13: Protected dashboard rejects unauthenticated request (status 401)
    // -------------------------------------------------------------
    const res13 = await fetch(`${baseUrl}/api/auth/dashboard`);
    assert(res13.status === 401, "13. Protected dashboard endpoint rejects unauthenticated access (status 401)");

    // -------------------------------------------------------------
    // Test 14: Protected dashboard grants access with verified JWT token (status 200)
    // -------------------------------------------------------------
    const res14 = await fetch(`${baseUrl}/api/auth/dashboard`, {
      headers: { Authorization: `Bearer ${verifiedJwtToken}` }
    });
    const d14 = await res14.json();
    assert(res14.status === 200 && d14.success && d14.user && d14.securityStatus?.emailVerified === true, "14. Protected dashboard delivers verified user workspace (status 200)");

    // -------------------------------------------------------------
    // Test 15: Logout clears session cookie (status 200)
    // -------------------------------------------------------------
    const res15 = await fetch(`${baseUrl}/api/auth/logout`, { method: "POST" });
    const d15 = await res15.json();
    assert(res15.status === 200 && d15.success, "15. Logout endpoint successfully clears session cookie (status 200)");

    // Cleanup: Remove test user
    try {
      const mongoose = require("mongoose");
      if (mongoose.connection && mongoose.connection.readyState === 1) {
        const UserModel = require("./models/User");
        await UserModel.deleteOne({ email: testEmail });
      }
      const accounts = readJsonAccounts();
      const filtered = accounts.filter((a) => a.email.toLowerCase() !== testEmail.toLowerCase());
      writeJsonAccounts(filtered);
    } catch (_) {}

  } catch (err) {
    console.error("Test execution caught an unexpected error:", err);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    console.log(`\n=======================================================`);
    console.log(`🏁 TEST SUMMARY: ${testPassed}/${testTotal} PASSED`);
    console.log(`=======================================================\n`);
    process.exit(testPassed === testTotal ? 0 : 1);
  }
}

runTests();
