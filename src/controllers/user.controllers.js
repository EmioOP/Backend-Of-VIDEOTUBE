import { asyncHAndler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from 'jsonwebtoken'


const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }
    } catch (error) {
        throw new ApiError(500, "something went wrong while access and refresh token creation")
    }
}

const userRegister = asyncHAndler(async (req, res) => {
    //get details from front end 
    //validation like empty  wrong fromat etc.
    //checking user is alredy excist 
    //checking for images 
    // upload on cloudinary
    // create user object and create entry in db
    // remove password and refresh token from field of response
    // check for user creation
    //response res.


    const { username, email, fullName, password } = req.body

    if ([username, email, fullName, password].some((field) => field.trim === "")) {
        throw new ApiError(400, "All field Are required")
    }


    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })


    if (existedUser) {
        throw new ApiError(409, "Username or Email is already excist")
    }

    const avatarLocalPath = req.files?.avatar[0].path;

    // const 
    let coverImageLocalFilePath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalFilePath = req.files.coverImage[0].path
    }


    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required")
    }


    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalFilePath)


    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }


    const user = await User.create({
        fullName,
        email,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        username: username.toLowerCase(),
        password
    })


    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )


    if (!createdUser) {
        throw new ApiError(500, "Something went wrong in user Creation")
    }



    return res.status(201).json(
        new ApiResponse(200, createdUser, "User Registered Successfully")
    )


})

const loginUser = asyncHAndler(async (req, res) => {

    // todos
    //get email or username and password from from end
    //check if the user exist or not
    //password check
    //access and referesh token
    //send cookie


    const { username, email, password } = req.body

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{ email }, { username }]
    })

    if (!user) {
        throw new ApiError(400, "User not found")
    }

    const isPasswordValid = user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(400, "Wrong Password")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-passwors -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, {
                user: loggedInUser, accessToken, refreshToken
            }, "User logged in SuccessFully")

        )



})

const logoutUser = asyncHAndler(async (req, res) => {

    await User.findByIdAndUpdate(req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "user log out"))

})

const refreshAccessToken = asyncHAndler(async (req, res) => {
    const incomingRefreshToken = req.cookie?.refreshToken || req.body?.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(400, "RefreshToken not found")
    }

    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

    if (!decodedToken) {
        throw new ApiError(400, "Unauthorized request")
    }

    const user = await User.findById(decodedToken._id)

    if (!user) {
        throw new ApiError(400, "Invalid refreshToken")
    }

    if (incomingRefreshToken !== user?.refreshToken) {
        throw new ApiError(400, "refreshToken Expired")
    }

    const { accessToken, newRefreshToken } = await generateAccessAndRefreshToken(user._id)


    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, {
                accessToken,
                refreshToken: newRefreshToken
            }, "accessToken refreshed successfully")
        )


})

const updatePassword = asyncHAndler(async (req, res) => {
    const { oldPassword, newPassword } = req.body

    if (!oldPassword || !newPassword) {
        throw new ApiError(400, "All fileds are requird")
    }

    const user = await User.findById(req.user._id)

    if (!user) {
        throw new ApiError(400, "Unauthorized request")
    }

    const validatePassword = await user.isPasswordCorrect(oldPassword)

    if (!validatePassword) {
        throw new ApiError(400, "Old password is wrong")
    }

    user.password = newPassword
    await user.save({ validateBeforeSave: false })

    return res
        .status(200)
        .json(
            new ApiResponse(200, {}, "password changed")
        )
})

const getCurrentUser = asyncHAndler(async(req,res)=>{
    return res
        .status(200)
        .json(
            new ApiResponse(200,
                req.user,
                "User fetched successfully"
                )
        )
})

const updateAccountDetails = asyncHAndler(async(req,res)=>{
    const {email,fullName} = req.body

    if(!email || !fullName){
        throw new ApiError(400, "all fields are required")
    }

    const user = await User.findByIdAndUpdate(req.user._id,
        {
            $set:{
                email,
                fullName:fullName
            }
        },
        {new:true}
        ).select("-password")

    if(!user){
        throw new ApiError(400,"Unauthorized Request")
    }

    return res
        .status(200)
        .json(
            new ApiError(200,user,"Account details updated")
        )
})

const updateUserAvatar = asyncHAndler(async(req,res)=>{

    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400,"avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar){
        throw new ApiError(400,"avatar is required")

    }

    //public id will extracted from cloudinary url

    const user = await User.findByIdAndUpdate(req.user._id,
        {
            $set:{
                avatar:avatar?.url
            }
        },
        {new:true}).select("-password")

    if (!user) {
        throw new ApiError(400,"unauthorized request")
    }

    return res
        .status(200)
        .json(
            new ApiResponse(200,user,"cover image updated")
        )
})

const updateUserCoverImage = asyncHAndler(async(req,res)=>{
     const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400,"avatar file is required")
    }

    const coverImage = await uploadOnCloudinary(avatarLocalPath)

    if(!coverImage){
        throw new ApiError(400,"avatar is required")

    }

    //public id will extracted from cloudinary url

    const user = await User.findByIdAndUpdate(req.user._id,
        {
            $set:{
                avatar:avatar?.url
            }
        },
        {new:true}).select("-password")

    if (!user) {
        throw new ApiError(400,"unauthorized request")
    }

    return res
        .status(200)
        .json(
            new ApiResponse(200,user,"cover image updated")
        )
    
})




export {
    userRegister,
    loginUser,
    logoutUser,
    refreshAccessToken,
    updatePassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}