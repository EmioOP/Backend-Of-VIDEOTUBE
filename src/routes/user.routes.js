import { Router } from "express";
import {  userRegister,loginUser,logoutUser } from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
import { validateJWT } from "../middlewares/auth.middleware.js";
const router = Router()


router.route("/register").post(upload.fields([
    {
        name:"avatar",
        maxCount: 1
    },
    {
        name:"coverImage",
        maxCount:1
    }
]),userRegister)

router.route("/login").post(loginUser)

//secured routes

router.route("/logout").post(validateJWT,logoutUser)


export default router