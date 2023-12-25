import { ApiError } from "../utils/ApiError.js";
import jwt from 'jsonwebtoken'
import { asyncHAndler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js";



export const validateJWT = asyncHAndler(async(req,res,next)=>{
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        console.log(token)
        if(!token){
            throw new ApiError(401,"Unauthorized request")
        }
    
        const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    
    
        const user = await User.findById(decodedToken?._id).select(
            "-password -refreshToken"
        )
    
        if(!user){
            throw new ApiError(401,"Invalid Access Token")
        }
    
        req.user = user
        next()

    } catch (error) {

        throw new ApiError(401,error.message || "invalid access Token")
    }

    
})