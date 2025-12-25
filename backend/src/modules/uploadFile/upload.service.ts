import { Request, Response, NextFunction } from "express";
import { AppError } from "../../Utils/AppError";
import cyberService from "../CyberSecurity/cyber.service";
import aiService from "../Ai/ai.service";
import path from "path";
import fs from "fs";

class UploadService {
  private cyberService = cyberService;
  private aiService = aiService;

  // رفع الملف + الفحص + التلخيص
  upload = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const sessionId = (req as any).sessionId; // لو عامل middleware بيحط sessionId على req
      const file = (req as any).file as Express.Multer.File | undefined;

      console.log("Uploaded file:", file);

      if (!sessionId || !file || !file.path) {
        throw new AppError("Upload failed: missing sessionId or file", 400);
      }

      const filePath = file.path;

      // 1) CyberSecurity scan
      const report = await this.cyberService.scan(sessionId, filePath);
      if (report.risk_level == 3) {
        return res.status(400).json({
          message: "Rejected file",
          report,
        });
      }

      // 2) AI summarize
      const summarization = await this.aiService.summarize(sessionId, filePath);

      return res.status(200).json({
        status: "success",
        sessionId,
        report,
        summarization,
      });
    } catch (error) {
      next(error);
    }
  };

  // سؤال على الـ PDF/الملخص
  askQuestion = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { question } = req.body;
      const { sessionId } = req.params;

      if (!sessionId || !question) {
        throw new AppError("Missing sessionId or question", 400);
      }
      const filePath = path.join("uploads", sessionId);
      if (!fs.existsSync(filePath))
        return res.status(400).json({ message: "Session Folder Not Found" });

      // Call AI service
      const chat = await aiService.askQuestion(sessionId, question);

      return res.status(200).json(chat);
    } catch (error) {
      next(error);
    }
  };
}

export default new UploadService();
