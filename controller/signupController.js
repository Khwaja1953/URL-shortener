const User = require("../model/signupModel"); // avoid naming conflict
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
require('dotenv').config();
const { setUser } = require("../services/auth");
const jwt = require('jsonwebtoken');
const logger = require('../services/log');
const multer = require("multer");
const fs = require("fs");
const path = require("path");



async function handleUserSignup(req, res) {
try{
  const { username, email, password } = req.body;
  // const profile = req.file.filename;
  // console.log(profile,username,email,password);
  if (!username  || !email || !req.file || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }
  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: "Username or Email already exists" });
    }
  const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
let otp = Math.floor(1000 + Math.random() * 9000).toString();
 await transporter.sendMail({
    from: process.env.EMAIL_USER, // sender address
    to: email,
    subject: "OTP for password Reset",
    text: `your otp is ${otp} please dont share it with anyone`, // plain‑text body
    
  });

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  const hashedOtp = bcrypt.hashSync(otp, 10);
   const authToken = jwt.sign(
      {
        username,
        email,
        password: hashedPassword,
        fileBuffer: req.file.buffer.toString("base64"), // keep file in token
        originalName: req.file.originalname,
        hashedOtp,
      },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );
  return res.render("signupValidateOtp.ejs",{authToken: authToken});
}catch(err){
  logger.error('Error during user signup: ' + err.message);
  logger.warn("warning in singup", err)
  return res.status(500).json({error: "Internal server error"});
}
}


async function handleSignupValidateOTP(req,res){
  try{
  const {authToken, otp}= req.body;
  // console.log(OTP)
  if(!otp || !authToken){
    return res.render("signupValidateOtp.ejs",{
      error:"OTP and AuthToken are required"
    })
  }
  let decodeToken;
  try{
    decodeToken = jwt.verify(authToken, process.env.JWT_SECRET);
  }catch(err){
    return res.render("signupValidateOtp.ejs",{
      error:"Invalid or expired token"
    })
  }
  
  const isOtpValid = bcrypt.compareSync(otp, decodeToken.hashedOtp);
  if (!isOtpValid) {
    return res.render("signupValidateOtp.ejs", {
      error: "Invalid OTP"
    });
  }
  const uploadsDir = path.join(__dirname, "../uploads");
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir);
    }

    const fileName = Date.now() + "-" + decodeToken.originalName;
    const filePath = path.join(uploadsDir, fileName);

    fs.writeFileSync(filePath, Buffer.from(decodeToken.fileBuffer, "base64"));

  
  // OTP is valid, proceed with signup
  await User.create({
    username: decodeToken.username,
    email: decodeToken.email,
    password: decodeToken.password,
    profile: decodeToken.profile
  });
  return res.redirect('/');}
  catch(err){
    logger.error('Error during OTP validation: ' + err.message);
    return res.status(500).json({error: "Internal server error"});
  }
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



async function handleForgotPassword(req, res) {
  try{
  const { email } = req.body;
  const user = await User.findOne({ email });


  if (!user) {
    logger.error(`Password reset requested for non-existent email: ${email}`);
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
}catch(err){
  logger.error('Error during forgot password process: ' + err.message);
  return res.status(500).json({error: "Internal server error"});}
}

async function handleVerifyOtp(req, res) {
  try{
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
}catch(err){
  logger.error('Error during OTP verification: ' + err.message);
  return res.status(500).json({error: "Internal server error"});
}}

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
module.exports = { handleUserSignup, handleUserLogin, handleForgotPassword, handleVerifyOtp, handleResetPassword, handleSignupValidateOTP };