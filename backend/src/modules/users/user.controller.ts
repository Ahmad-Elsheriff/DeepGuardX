import { Router } from "express";
import US from "./user.service";
import { generateSessionId } from "../../middleware/SessionId";
import { allowedExtensions, MulterLocal } from "../../middleware/Multer";

const userRouter = Router()

userRouter.post('/signUp', US.signUp)
userRouter.post('/signIn', US.signIn)



export default userRouter