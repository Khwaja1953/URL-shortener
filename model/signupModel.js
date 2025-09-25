const mongoose = require("mongoose");

const Schema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    role: { type: String, enum: ['ADMIN', 'NORMAL'], default: 'NORMAL' },
    profileImage: {type: String},
    passwordResetToken: {
        type: String,
    },
    passwordResetExpires: {
        type: Date,
    }

});
module.exports = mongoose.model('User', Schema)


