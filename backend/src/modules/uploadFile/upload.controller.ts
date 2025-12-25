import { Router } from "express";
import US from "./upload.service";
import { generateSessionId } from "../../middleware/SessionId";
import { allowedExtensions, MulterLocal } from "../../middleware/Multer";

const uploadRouter = Router()

uploadRouter.post('/', generateSessionId(), MulterLocal({customExtensions: allowedExtensions.pdf}).single('file'), US.upload)
uploadRouter.post('/ask/:sessionId', US.askQuestion)

export default uploadRouter