const Url = require('../model/urlmodel');
const { nanoid } = require('nanoid');
const logger = require("../services/log");



exports.createShortUrl = async (req, res) => {
    try {
        const { originalUrl } = req.body;
        const shortId = nanoid(6);
        logger.http(`${req.method} ${req.url} - ${req.ip}`);
        await Url.create({ originalUrl: originalUrl, shortId: shortId ,createdBy: req.user._id});

        // Fetch all URLs again
        const allUrls = await Url.find({ createdBy: req.user._id });
        
        // Pass both id and url list
        // res.status(201).json({ id });
        res.render('home', { shortId, url: allUrls });
    } catch (err) {
        console.error('Error creating short URL:', err.message);
        res.status(500).send('Internal Server Error');
    }
};


exports.redirectUrl = async (req, res) => {
    try {
        const { id } = req.params;
        const record = await Url.findOne({ shortId: id });

        if (record) {
            res.redirect(record.originalUrl);
        } else {
            res.status(404).send('URL not found');
        }
    } catch (err) {
        res.status(500).send('Server Error');
    }
};
