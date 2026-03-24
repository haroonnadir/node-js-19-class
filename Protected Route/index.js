const express = require("express");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const jwt = require("jsonwebtoken");
const User = require("./model/user.model.js");

const app = express();
const JWT_SECRET = "SUPER_SECRET_KEY";
const TOKEN_EXPIRY = "1m"; // better than 20s for demo

// ================= DATABASE =================
mongoose.connect("mongodb://127.0.0.1:27017/user_database")
  .then(() => console.log("DB Connected"))
  .catch(err => console.log(err));

// ================= MIDDLEWARE =================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use(cookieParser());

// ================= CSRF =================
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// ================= VIEW ENGINE =================
app.set("view engine", "ejs");


// ================= JWT AUTH MIDDLEWARE =================
const verifyJWT = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select("-userpassword");
    if (!user) {
      res.clearCookie("token");
      return res.redirect("/login");
    }

    req.user = user;
    next();

  } catch (err) {
    res.clearCookie("token");
    return res.redirect("/login");
  }
};

// ================= ROLE MIDDLEWARE =================
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("Access Denied (Admin Only)");
  }
  next();
};

// ================= ROUTES =================

// Root
app.get("/", (req, res) => res.redirect("/login"));

// -------- REGISTER --------
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    const { username, useremail, userpassword } = req.body;

    const exists = await User.findOne({ useremail });
    if (exists) {
      return res.render("register", { error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(userpassword, 10);

    await User.create({
      username,
      useremail,
      userpassword: hashedPassword,
      role: "user" // default role
    });

    res.redirect("/login");

  } catch (err) {
    res.render("register", { error: "Server error" });
  }
});

// -------- LOGIN --------
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  try {
    const { useremail, userpassword } = req.body;

    const user = await User.findOne({ useremail });
    if (!user) return res.render("login", { error: "User not found" });

    const isMatch = await bcrypt.compare(userpassword, user.userpassword);
    if (!isMatch) return res.render("login", { error: "Incorrect password" });

    const token = jwt.sign(
      { id: user._id },
      JWT_SECRET,
      { expiresIn: TOKEN_EXPIRY }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // true in production (HTTPS)
      sameSite: "strict",
      maxAge: 60 * 1000
    });

    res.redirect("/home");

  } catch (err) {
    res.render("login", { error: "Server error" });
  }
});

// ================= PROTECTED ROUTES =================

// User Home
app.get("/home", verifyJWT, (req, res) => {
  res.render("home", { user: req.user });
});

// Dashboard
app.get("/dashboard", verifyJWT, (req, res) => {
  res.send(`Welcome ${req.user.username} to Dashboard`);
});

// Profile
app.get("/profile", verifyJWT, (req, res) => {
  res.send(`Profile Page of ${req.user.username}`);
});

// Admin Route
app.get("/admin", verifyJWT, verifyAdmin, (req, res) => {
  res.send("Admin Panel");
});

// Logout
app.post("/logout", verifyJWT, (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

// ================= CSRF ERROR =================
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF Token");
  }
  next(err);
});

// ================= SERVER =================
app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);