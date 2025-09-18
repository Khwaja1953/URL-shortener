const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const cookieParser = require("cookie-parser");
const urlRoute = require('./routes/urlroutes'); 
const signUproutes = require('./routes/signupROutes')
const staticRoute = require('./routes/staticRouter')
const { checkAuthentication,restrictTo} = require("./middlewares/auth");



dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error('MONGO_URI missing from .env');
    process.exit(1);
}

app.set("view engine", "ejs");
app.set("views", path.resolve("./views"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // required for form parsing
app.use(checkAuthentication)

app.use("/user", signUproutes,);

app.use("/url",restrictTo(["NORMAL","ADMIN"]),urlRoute);
app.use("/", staticRoute);


mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => {
        console.error('MongoDB connection error:', err.message);
        process.exit(1);
    });

app.listen(PORT, () => {
    console.log(` Server is running at http://localhost:${PORT}`);
});
