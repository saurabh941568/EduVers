// Importing required modules
const jwt = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/User");
// Configuring dotenv to load environment variables from .env file


// This function is used as middleware to authenticate user requests
exports.auth = async (req, res, next) => {
    try {
        // Extracting JWT from request cookies, body or header
        const token =
            req.cookies.token ||
            req.body.token ||
            req.header("Authorization").replace("Bearer ", "");

        // If JWT is missing, return 401 Unauthorized response
        if (!token) {
            return res.status(401).json({
                success: false,
                message: `Token Missing` });
        }

        //verify the token
        try {
            // Verifying the JWT using the secret key stored in environment variables
            const decode = await jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            // Storing the decoded JWT payload in the request object for further use
            req.user = decode;
        } catch (error) {
            // If JWT verification fails, return 401 Unauthorized response
            return res.status(401).json({ 
                success: false, 
                message: "token is invalid" });
        }

        // If JWT is valid, move on to the next middleware or request handler
        next();
    } catch (error) {
        // If there is an error during the authentication process, return 401 Unauthorized response
        return res.status(401).json({
            success: false,
            message: `Something Went Wrong While Validating the Token`,
        });
    }
};
// These functions are used as middleware to authorise user requests
//verify the role if the user is a student
exports.isStudent = async (req, res, next) => {
    try {
        const userDetails = await User.findOne({ email: req.user.email });

        if (userDetails.accountType !== "Student") {
            return res.status(401).json({
                success: false,
                message: "This is a Protected Route for Students",
            });
        }
        next();
    } catch (error) {
        return res.status(500).json({ 
            success: false, 
            message: `User Role Can't be Verified` });
    }
};
//verify the role if the user is an Admin
exports.isAdmin = async (req, res, next) => {
    try {
        const userDetails = await User.findOne({ email: req.user.email });

        if (userDetails.accountType !== "Admin") {
            return res.status(401).json({
                success: false,
                message: "This is a Protected Route for Admin",
            });
        }
        next();
    } catch (error) {
        return res
            .status(500)
            .json({ success: false, message: `User Role Can't be Verified` });
    }
};
//verify the role if the user is an Instructor
exports.isInstructor = async (req, res, next) => {
    try {
        const userDetails = await User.findOne({ email: req.user.email });
        console.log(userDetails);

        console.log(userDetails.accountType);

        if (userDetails.accountType !== "Instructor") {
            return res.status(401).json({
                success: false,
                message: "This is a Protected Route for Instructor",
            });
        }
        next();
    } catch (error) {
        return res
            .status(500)
            .json({ success: false, message: `User Role Can't be Verified` });
    }
};