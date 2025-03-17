const express = require("express");
const router = express.Router();
const { register, verifyEmail, login, refreshToken, logout, forgotPassword, resetPassword } = require("../controllers/authController");

router.post("/register", register);
router.get("/verify-email/:token", verifyEmail);
router.post("/login", login);
router.get("/refresh-token", refreshToken);
router.post("/logout", logout);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

module.exports = router;