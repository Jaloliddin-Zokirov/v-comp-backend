// server.js – serverni sozlash
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const authRoutes = require("./routers/authRouters");

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(cookieParser());

// API Rate Limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Ko‘p so‘rov yuborildi, keyinroq urinib ko‘ring",
});
app.use(limiter);

// Routes
app.use("/api", authRoutes);

// Bosh sahifa route
app.get("/", (req, res) => {
  res.send("Kompyuter do‘konining backend serveri ishlamoqda!");
});

module.exports = app;