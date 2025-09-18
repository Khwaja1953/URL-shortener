const express = require('express');
const { handleUserSignup, handleUserLogin } = require('../controller/signupController');
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

module.exports = router;
