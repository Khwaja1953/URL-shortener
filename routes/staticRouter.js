const express = require('express');
const URL = require('../model/urlmodel');
const { restrictTo } = require('../middlewares/auth');

const router = express.Router();
router.get('/admin/urls',restrictTo("ADMIN"),async (req, res) => {
    try {
      if (!req.user) return res.redirect("/login");

        const allUrls=await URL.find({});

        // Send a response only once
        return res.render("home", {
            url: allUrls,

        });

        // Or if you want to return JSON instead:
        // return res.status(200).json(allUrls);

    } catch (error) {
        console.error("Error fetching URLs:", error);

        return res.status(500).json({
            message: 'Error fetching URLs',
            error: error.message  // safer than sending full error object
        });
    }
});
router.get('/',restrictTo(["NORMAL","ADMIN"]), async (req, res) => {
    try {
        // console.log(req.user);
      if (!req.user) return res.redirect("/login");

        const allUrls=await URL.find({createdBy: req.user._id });

        // Send a response only once
        return res.render("home", {
            url: allUrls,

        });

        // Or if you want to return JSON instead:
        // return res.status(200).json(allUrls);

    } catch (error) {
        console.error("Error fetching URLs:", error);

        return res.status(500).json({
            message: 'Error fetching URLs',
            error: error.message  // safer than sending full error object
        });
    }
});


router.get('/signup', (req, res) => {
    return res.render('Signup');
})
router.get('/login', (req, res) => {
    return res.render('login');
});
router.get('/forgotpassword', (req, res) => {
    return res.render('forgotpassword');
});
router.get('/resetpassword', (req, res) => {
    return res.render('resetpassword');
});
router.get('/verifyotp', (req, res) => {
    return res.render('verifyotp');
});

module.exports = router