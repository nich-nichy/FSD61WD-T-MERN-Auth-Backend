const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const morgan = require('morgan');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8081;

app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(cors());

// connect to MongoDB
const connectDB = async () => {
    try {
        if (mongoose.connection.readyState === 1) {
            console.log('MongoDB is already connected.');
            return;
        }
        await mongoose.connect(process.env.DB_URL, {});
        console.log('MongoDB connected successfully!');
    } catch (err) {
        console.error('Error connecting to MongoDB:', err);
    }
};

connectDB();

// Routes
app.get('/', (req, res) => {
    res.send(`Backend for app is running on ${port}`);
})

app.use("/auth", require("./routers/userAuth.route.js"));

// Route Error handling
app.use((req, res, next) => {
    const error = {
        status: 404,
        message: "Check route and method",
    };
    next(error);
});

// Error handling in controller
app.use((error, req, res, next) => {
    res.status(error.status || 500);
    console.log("ERROR", error);
    res.json({
        error: {
            message: error.message,
            status: error.status,
        },
    });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
})