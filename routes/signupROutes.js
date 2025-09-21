const express = require('express');
const { handleUserSignup, handleUserLogin, handleForgotPassword, handleVerifyOtp, handleResetPassword } = require('../controller/signupController');
const router = express.Router();
const multer = require("multer");
// const upload = multer({ dest: './uploads' });
const storage = multer.diskStorage({

     destination:function (req, file, cb){
        cb(null, './uploads')
     },
     filename: function (req, file, cb) {
        
        cb(null, Date.now()+ file.originalname)
     }
})
const upload = multer({storage})

router.post('/createuser',upload.single('profileImage'), handleUserSignup);
router.post('/loginuser', handleUserLogin)
router.post('/forgotpassword', handleForgotPassword)
router.post('/verifyotp', handleVerifyOtp);
router.post('/resetpassword',handleResetPassword)

module.exports = router;
