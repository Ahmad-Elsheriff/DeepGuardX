import express, { NextFunction, Request, Response } from 'express'
import helmet from 'helmet'
import cors from 'cors'
import { rateLimit } from 'express-rate-limit'
import { AppError } from './Utils/AppError'
import userRouter from './modules/users/user.controller'
import aiRouter from './modules/Ai/ai.controller'
import cyberRouter from './modules/CyberSecurity/cyber.controller'
import uploadRouter from './modules/uploadFile/upload.controller'

const app: express.Application = express()
const port: string | number = process.env.PORT || 8000

const whitelist: (string | undefined)[] = [process.env.FRONT_END, undefined]
const corsOptions = {
  origin: (origin: string | undefined, callback: Function) => {
    if (whitelist.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not Allowed by CORS"));
  }
};

const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 20, 
  message: {
    error: 'Many Requests, Try again later 🤫'
  },
  skipSuccessfulRequests: true,
  legacyHeaders: false,
  statusCode: 429
})

const bootstrap = () => {
  app.use('/uploads', express.static("uploads"))
  app.use(express.json())
  app.use(helmet())
  app.use(cors(corsOptions))
  app.use(limiter)
  console.log(process.env.FRONT_END)
  app.get('/', (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json({ message: 'Welcome to our app 😁' })
  })

  app.use('/users', userRouter)
  app.use('/Ai', aiRouter)
  app.use('/cyber', cyberRouter)
  app.use('/upload', uploadRouter)

  // تم استبدال app.all بالدالة دي لأنها مش محتاجة Path فتجنبنا الـ PathError تماماً
  app.use((req: Request, res: Response, next: NextFunction) => {
    next(new AppError(`InValid Url ${req.originalUrl}`, 404))
  })

  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    return res.status(err.statusCode || 500).json({ 
        message: err.message, 
        stack: err.stack, 
        error: err 
    })
  })

  const server = app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
  });

  // إعدادات التايم أوت الأساسية لحل مشكلة الـ AI
  server.timeout = 600000; 
  server.keepAliveTimeout = 600000;
  server.headersTimeout = 601000; 
}

export default bootstrap