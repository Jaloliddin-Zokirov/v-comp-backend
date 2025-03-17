const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");

const register = async (req, res) => {
  try {
    const { email, parol } = req.body;

    const mavjudUser = await User.findOne({ email });
    if (mavjudUser) {
      return res
        .status(400)
        .json({ message: "Bu email allaqachon ro‘yxatdan o‘tgan" });
    }

    const hashedPassword = await bcrypt.hash(parol, 10);
    const user = new User({ email, parol: hashedPassword });
    await user.save();

    // Email verification token
    const emailToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    const verifyLink = `${process.env.CLIENT_URL}/verify-email/${emailToken}`;

    await sendEmail(
      email,
      "Email tasdiqlash",
      `<p>Assalomu alaykum, ro‘yxatdan o‘tishni tasdiqlash uchun quyidagi havolaga bosing:</p>
       <a href="${verifyLink}">${verifyLink}</a>`
    );

    res.status(201).json({
      message:
        "Foydalanuvchi ro‘yxatdan o‘tdi. Email tasdiqlash linki yuborildi.",
    });
  } catch (err) {
    res.status(500).json({ message: "Serverda xatolik" });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ message: "Noto‘g‘ri token" });
    }

    user.emailTasdiqlangan = true;
    await user.save();

    res.status(200).json({ message: "Email muvaffaqiyatli tasdiqlandi" });
  } catch (err) {
    res.status(400).json({ message: "Token muddati tugagan yoki noto‘g‘ri" });
  }
};

const login = async (req, res) => {
  try {
    const { email, parol } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email yoki parol noto‘g‘ri" });
    }

    if (!user.emailTasdiqlangan) {
      return res.status(403).json({ message: "Email tasdiqlanmagan" });
    }

    const isMatch = await bcrypt.compare(parol, user.parol);
    if (!isMatch) {
      return res.status(400).json({ message: "Email yoki parol noto‘g‘ri" });
    }

    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Refresh tokenni cookie orqali yuboramiz
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // productionda true
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 kun
    });

    res.status(200).json({ accessToken, message: "Muvaffaqiyatli kirildi" });
  } catch (err) {
    res.status(500).json({ message: "Serverda xatolik" });
  }
};

const refreshToken = (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) {
    return res.status(401).json({ message: "Refresh token topilmadi" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ message: "Noto‘g‘ri yoki eskirgan refresh token" });
  }
};

const logout = (req, res) => {
  res.clearCookie("refreshToken", { httpOnly: true, sameSite: "strict" });
  res.status(200).json({ message: "Chiqish muvaffaqiyatli bo‘ldi" });
};

// 1. Forgot Password
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Bunday email topilmadi" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 daqiqa

    await user.save();

    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    const message = `
        <h3>Parolni tiklash</h3>
        <p>Quyidagi havola orqali parolingizni tiklashingiz mumkin:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>Havola 10 daqiqa ichida amal qiladi.</p>
      `;

    await sendEmail({
      to: user.email,
      subject: "Parolni tiklash",
      html: message,
    });

    res
      .status(200)
      .json({ message: "Parol tiklash havolasi emailga yuborildi" });
  } catch (err) {
    res.status(500).json({ message: "Serverda xatolik" });
  }
};

// 2. Reset Password
const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { yangiParol } = req.body;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Token noto‘g‘ri yoki muddati o‘tgan" });
    }

    const hashedPassword = await bcrypt.hash(yangiParol, 10);
    user.parol = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(200).json({ message: "Parol muvaffaqiyatli tiklandi" });
  } catch (err) {
    res.status(500).json({ message: "Serverda xatolik" });
  }
};

module.exports = {
  register,
  verifyEmail,
  login,
  refreshToken,
  logout,
  forgotPassword,
  resetPassword,
};
