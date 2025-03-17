const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB muvaffaqiyatli ulandi");
  } catch (err) {
    console.error("MongoDB ulanishda xatolik:", err.message);
    process.exit(1);
  }
};

module.exports = connectDB;