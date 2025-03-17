// index.js – faqat serverni ishga tushuradi
const app = require("./src/server");
const connectDB = require("./src/config/db");

const PORT = process.env.PORT || 5000;

connectDB();

app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishga tushdi`);
});