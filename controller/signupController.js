const User = require("../model/signupModel"); // avoid naming conflict
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
require('dotenv').config();
const { setUser} = require("../services/auth");


async function handleUserSignup(req, res) {
  const salt = bcrypt.genSaltSync(10);
  const password = bcrypt.hashSync(req.body.password, salt);
  // console.log(req.file);
    const { username, email } = req.body;
    const profileImage = req.file.filename;
     if (!username || !password || !email) {
            return res.status(400).json({ error: "All fields are required" });
        }

    await User.create({
        username,
        email,
        password,
        profileImage
    });
    return res.redirect('/');

}


async function handleUserLogin(req, res) {
  const { username, password } = req.body;
  // console.log(username, password);
  const user = await User.findOne({ username});
  
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.render("login", {
      error: "Invalid Username or Password",
    });

  
  const token=setUser(user);
  res.cookie("uid", token);

  return res.redirect("/");
  // return res.json({token});
}
let otpStore = { email: null, otp: null };

// Function to generate a 4-digit OTP
function generateOtp() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

async function handleForgotPassword(req, res) {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // Generate OTP and store email + OTP temporarily
  const otp = generateOtp();
  otpStore = { email, otp }; // store for verification

  // Send OTP via email
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, // App password
    },
  });

  const info = await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "OTP for password reset",
    text: `Your OTP is ${otp}`,
  });

  console.log("Email sent:", info.messageId);
  res.render("verifyotp"); // Show OTP entry form
}

async function handleVerifyOtp(req, res) {
  const { otp } = req.body;
  console.log(otp, otpStore.otp);

  if (otp === otpStore.otp) {
    // ✅ OTP is correct → render reset password form
    res.render("resetpassword");
  } else {
    return res.status(400).send("Invalid OTP. Please try again.");
  }
}

async function handleResetPassword(req, res) {
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send("Passwords do not match");
  }

  if (!otpStore.email) {
    return res.status(400).send("Session expired. Please try again.");
  }

  // Find the user from stored email
  const user = await User.findOne({ email: otpStore.email });

  if (!user) {
    return res.status(404).send("User not found");
  }

  // ⚠️ In production: hash password before saving
  const salt = bcrypt.genSaltSync(10);
 
  user.password = bcrypt.hashSync(password, salt);
  console.log(user.password);
  await user.save();

  // Clear OTP store after use
  otpStore = { email: null, otp: null };

  res.send("Password updated successfully! You can now log in.");
}
module.exports = { handleUserSignup, handleUserLogin, handleForgotPassword, handleVerifyOtp, handleResetPassword }