// Required modules
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs"); // ใช้ bcrypt สำหรับการเข้ารหัสรหัสผ่าน
const jwt = require("jsonwebtoken"); // ใช้ jsonwebtoken สำหรับการสร้างและตรวจสอบ JWT
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config(); // โหลด environment variables จากไฟล์ .env

const blacklistedTokens = require("./blacklist");
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware setup
app.use(cors()); // เปิดใช้งาน CORS
app.use(bodyParser.json()); // ใช้ body-parser เพื่อแปลง request body เป็น JSON

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("Could not connect to MongoDB Atlas", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, default: "user" },
});

const User = mongoose.model("User", userSchema);

// Create a unique index with case-insensitive collation
userSchema.index({ username: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });

// Middleware for checking blacklist and verifying token
const verifyToken = (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).send("Authorization header missing or malformed");
    }

    if (blacklistedTokens.includes(token)) {
      return res.status(401).send("Token is blacklisted");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).send("Invalid token");
  }
};

// logout
app.post("/logout", verifyToken, (req, res) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  blacklistedTokens.push(token); // Add token to blacklist
  res.status(200).send("Logged out successfully"); // Ensure status is explicitly set to 200
});

app.get("/protected", verifyToken, (req, res) => {
  res.send("This is a protected route");
});


// Registration route
app.post("/register", async (req, res) => {
  try {
    let { username, password, email } = req.body;

    // Convert username to lowercase
    username = username.toLowerCase();

    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).send("User already exists");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      email,
    });

    // Save user
    const savedUser = await user.save();

    res.status(201).json({
      message: "Saved Successfully",
      result: true,
      data: savedUser._id, // or any other unique data you want to send
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error",
      result: false,
    });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    // Convert username to lowercase
    username = username.toLowerCase();

    // Find user with case-insensitive collation
    const user = await User.findOne({ username }).collation({ locale: 'en', strength: 2 });
    if (!user)
      return res.status(400).json({
        message: "UserName or Password is Wrong",
        result: false,
        data: null,
      });

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({
        message: "UserName or Password is Wrong",
        result: false,
        data: null,
      });

    // Generate JWT
    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Send success response
    res.json({
      message: "Login Success",
      result: true,
      data: {
        token: token,
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Server error", result: false, data: null });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
