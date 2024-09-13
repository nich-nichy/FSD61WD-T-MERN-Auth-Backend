const userSchema = require("../models/userAuth.model");
const { createSecretToken } = require("../utils/SecretToken");
const bcrypt = require("bcryptjs");
const crypto = require('crypto');
const nodemailer = require('nodemailer');

module.exports.SignupFunction = async (req, res, next) => {
    try {
        const { email, password, username, createdAt } = req.body;
        const existingUser = await userSchema.findOne({ email });
        if (existingUser) {
            return res.json({ message: "User already exists" });
        }
        const user = await userSchema.create({ email, password, username, createdAt });
        const token = createSecretToken(user._id);
        res.cookie("token", token, {
            withCredentials: true,
            httpOnly: true,
            secure: true,
            sameSite: 'None',
        });
        res
            .status(201)
            .json({ message: "User signed in successfully", success: true, user });
    } catch (error) {
        console.error(error);
    }
};

module.exports.LoginFunction = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        const user = await userSchema.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Incorrect password or email' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Incorrect password or email' });
        }
        const token = createSecretToken(user._id);
        console.log(token)
        res.cookie("token", token, {
            withCredentials: true,
            httpOnly: true,
            secure: true,
            sameSite: 'None',
        });
        res.status(200).json({ message: "User logged in successfully", success: true });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
};

module.exports.PasswordResetFunction = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await userSchema.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpiration = Date.now() + 3600000;
        await user.save();
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            }
        });
        console.log(process.env.APP_URL);
        const resetLink = `${process.env.APP_URL}/reset-password/${resetToken}`;
        console.log(resetLink);
        await transporter.sendMail({
            to: email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset (An Task)',
            html: `<p>You requested a password reset</p>
               <p>Click this <a href="${resetLink}">link</a> to reset your password</p>
               <p>This is a task </p>`
        });
        res.status(200).json({ message: 'Password reset link sent!' });
    } catch (error) {
        res.send(error);
    }
}

module.exports.UpdatePasswordFunction = async (req, res, next) => {
    try {
        const { newPassword } = req.body;
        const { token } = req.params;
        const user = await userSchema.findOne({ resetToken: token });
        if (!user) {
            return res.status(404).json({ message: 'Invalid or expired reset token' });
        }
        if (user.resetTokenExpiration < Date.now()) {
            return res.status(400).json({ message: 'Reset token has expired' });
        }
        user.password = newPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();
        res.status(200).json({ message: 'Password updated successfully', success: true });
    } catch (error) {
        console.error("Error during saving new password:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
};

