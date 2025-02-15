const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require("otp-generator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

//sendOtp
exports.sendOTP = async(req , res) => {
    try{
        //fetch email from request body
        const {email} = req.body;

        //check if user already exits
        const checkUserPresent = await User.findOne({email});

        //if user already exit,then return res

        if(checkUserPresent){
            return res.status(401).json({
                success : false,
                message :'User already register',
            })
        }
        //generate OTP
        let otp = otpGenerator.generate(6, {
            upperCaseAlphabets:false,
            lowerCaseAlphabets:false,
            specialChars:false,
        });
        console.log("OTP generated: ",otp);

        //check unique otp or not
        const result = await OTP.findOne({otp : otp});

        while(result){
            otp = otpGenerator.generate(6, {
                upperCaseAlphabets:false,
                lowerCaseAlphabets:false,
                specialChars:false,
            });
            result = await OTP.findOne({otp:otp});
        }

        const otpPayload = {email,otp};

        //create an entry in DB
        const otpBody = await OTP.create(otpPayload);
        console.log(otpBody);

        //return response successfull
        res.status(200).json({
            success:true,
            message:'OTP sent successfully',
            otp,
        })
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:error.message,
        });
    }
};

//signUp
exports.signUp = async(req,res) => {
    try{
        // data fetch
        const {
            firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        } = req.body;
        //validate krlo
        if(!firstName || !lastName || !email || !password || !confirmPassword ||  !otp){
            return res.status(403).json({
                success:false,
                message:"All field are required",
            })
        }
        // 2 password match krlo
        if(password !== confirmPassword){
            return res.status(400).json({
                success:false,
                message:'Password and ConfirmPassword value does not match,please try again'
            });
        }
        //check user already exit or not
        const existingUser = await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success:false,
                message:'User is already registerd',
            });
        }
        //find most recent OTP stored for the user
        const recentOtp = await OTP.find({email}).sort({createdAt:-1}).limit(1);
        console.log(recentOtp);
        //validate OTP
        if(recentOtp.length==0){
            //OTP not found
            return res.status(400).json({
                success:false,
                message:'OTP not found',
            })
        }else if(otp !== recentOtp.otp){
            //invalid otp
            return res.status(400).json({
                success:false,
                message:"Invalid otp",
            });
        }
        //hash password
        const hashedPassword = await bcrypt.hash(password,10);

        //entry create in DB
        const profileDetails = await Profile.create({
            gender:null,
            dateOfBirth:null,
            about:null,
            contactNumber:null,
        });

        const user = await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password:hashedPassword,
            accountType,
            additionalDetails:profileDetails._id,
            Image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,

        });

        //return res
        return res.status(200).json({
            success:true,
            message:'User is registered successfully',
            user,
        });
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"User cannot be registered .please try again",
        });
    }
}

// login
exports.login = async(req,res)=>{
    try{
        //get data from req body
        const {email,password}=req.body;
        //validation data
        if(!email || !password){
            return res.status(403).json({
                success:false,
                message:'All fields are required,please try again',
            });
        }
        //user check exist or not
        const user = await User.findOne({email}).populate("additinalDetails");
        if(!user){
            return res.status(401).json({
                success:false,
                message:"User is not registered ,please signUp first",
            });
        }
        //generate JWT,after password matching
        if(await bcrypt.compare(password,user.password)){
            const payload ={
                email:user.email,
                id:user._id,
                accountType:user.accountType,
            }
            const token = jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn:"2h",
            });
            user.token = token;
            user.password=undefined;

            //create cookie and send response
            const options = {
                expires: new Date(Date.now() + 3*24*60*1000),
                httpOnly:true,
            }
            res.cookie("token",token,options).status(200).json({
                success:true,
                token,
                user,
                message:'Logged in Successfully',
            });
        }
        else{
            return res.status(401).json({
                success:false,
                message:'Password in Incorrect',
            });
        }
        
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:'Login Failure,please try again',
        });
    }
};

//changePassword
exports.changePassword = async (req, res) => {
    try {
        // Get user data from req.user
        const userDetails = await User.findById(req.user.id)

        // Get old password, new password, and confirm new password from req.body
        const { oldPassword, newPassword } = req.body

        // Validate old password
        const isPasswordMatch = await bcrypt.compare(
            oldPassword,
            userDetails.password
        )
        if (!isPasswordMatch) {
            // If old password does not match, return a 401 (Unauthorized) error
            return res
                .status(401)
                .json({ success: false, message: "The password is incorrect" })
        }

        // Update password
        const encryptedPassword = await bcrypt.hash(newPassword, 10)
        const updatedUserDetails = await User.findByIdAndUpdate(
            req.user.id,
            { password: encryptedPassword },
            { new: true }
        )

        // Send notification email
        try {
            const emailResponse = await mailSender(
                updatedUserDetails.email,
                "Password for your account has been updated",
                passwordUpdated(
                    updatedUserDetails.email,
                    `Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
                )
            )
            console.log("Email sent successfully:", emailResponse.response)
        } catch (error) {
            // If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
            console.error("Error occurred while sending email:", error)
            return res.status(500).json({
                success: false,
                message: "Error occurred while sending email",
                error: error.message,
            })
        }

        // Return success response
        return res
            .status(200)
            .json({ success: true, message: "Password updated successfully" })
    } catch (error) {
        // If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
        console.error("Error occurred while updating password:", error)
        return res.status(500).json({
            success: false,
            message: "Error occurred while updating password",
            error: error.message,
        })
    }
}