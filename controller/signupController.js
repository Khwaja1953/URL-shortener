const User = require("../model/signupModel"); // avoid naming conflict
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
require('dotenv').config();
const { setUser } = require("../services/auth");
const jwt = require('jsonwebtoken');


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
  const user = await User.findOne({ username });

  if (!user || !bcrypt.compareSync(password, user.password))
    return res.render("login", {
      error: "Invalid Username or Password",
    });


  const token = setUser(user);
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
    return res.status(200).json({ message: "wrong email." });
  }

  // 1. Generate a simple 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // 3. Set expiration time (e.g., 10 minutes from now)
  const expiration = Date.now() + 10 * 60 * 1000;

  // 4. Save the  OTP and expiration to the user's document
  user.passwordResetToken = otp;
  user.passwordResetExpires = expiration;
  await user.save();

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

  // console.log(`Generated OTP for ${user.email}: ${otp}`); 

  res.render("verifyotp",{email: user.email}); // Show OTP entry form
}

async function handleVerifyOtp(req, res) {
  const { email, otp } = req.body;
  // console.log(otp, otpStore.otp);

 const user = await User.findOne({
            email,
            passwordResetToken: otp,
            passwordResetExpires: { $gt: Date.now() } // Check if the token is not expired
        });

         if (!user) {
            return res.status(400).json({ error: "Invalid or expired reset code." });
        }

  const authToken = jwt.sign(
            { userId: user._id }, // Payload includes user's ID
            process.env.JWT_SECRET,
            { expiresIn: '10m' }  // Token expires in 10 minutes
        );
        res.render("resetpassword",{authToken: authToken})
}

async function handleResetPassword(req, res) {
  const { password, confirmPassword , authToken} = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send("Passwords do not match");
  }

  let decodedToken;
        try {
            // This checks if the token is valid and not expired
            decodedToken = jwt.verify(authToken, process.env.JWT_SECRET);
        } catch (err) {
            // If the token is invalid or expired, the user must start over
            return res.status(400).render('forgot-password', {
                error: 'Your password reset link is invalid or has expired. Please request a new one.'
            });
        }

        const user = await User.findById(decodedToken.userId);
        if (!user) {
            return res.status(404).send('User not found.');
        }

  

  // ⚠️ In production: hash password before saving
  const salt = bcrypt.genSaltSync(10);

  user.password = bcrypt.hashSync(password, salt);
  console.log(user.password);
  await user.save();


  res.send("Password updated successfully! You can now log in.");
}
module.exports = { handleUserSignup, handleUserLogin, handleForgotPassword, handleVerifyOtp, handleResetPassword }