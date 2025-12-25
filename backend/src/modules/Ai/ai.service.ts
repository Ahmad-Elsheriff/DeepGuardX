import { NextFunction, Request, Response } from "express";
import { AppError } from "../../Utils/AppError";
import fs from "fs";
import path from "path";
import axios from "axios";
import FormData from "form-data";
import http from "http"; // استيراد مكتبة http للـ Agent
import https from "https";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  sources?: { source: string; page: number }[];
};

class AiService {
  private aiBaseUrl: string;

  constructor() {
    this.aiBaseUrl = process.env.AI_SERVICE_URL || "http://localhost:8000";
  }

  /**
   * Summarize a PDF file
   */
  async summarize(sessionId: string, filePath: string): Promise<string> {
    if (!sessionId || !filePath) {
      throw new AppError("Missing Session Id or filePath", 400);
    }

    if (!fs.existsSync(filePath)) {
      throw new AppError(`File not found: ${filePath}`, 404);
    }

    const stat = fs.lstatSync(filePath);
    if (stat.isDirectory()) {
      throw new AppError("Expected a file but got a directory", 400);
    }

    const sessionFolder = path.join("uploads", sessionId);
    if (!fs.existsSync(sessionFolder)) {
      fs.mkdirSync(sessionFolder, { recursive: true });
    }

    try {
      const formData = new FormData();
      formData.append("sessionId", sessionId);
      formData.append("file", fs.createReadStream(filePath));

      // إعداد الـ Axios مع Agent للحفاظ على الاتصال مفتوحاً (Keep-Alive)
      const response = await axios.post(
        `${this.aiBaseUrl}/api/summarize`,
        formData,
        {
          headers: {
            ...formData.getHeaders(),
          },
          // نضع التايم أوت 10 دقائق لأن الـ OCR والـ AI يحتاجان وقتاً
          timeout: 600000,
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
          // هذا هو الحل الصحيح لمشكلة الـ keepAlive التي ظهرت لك
          httpAgent: new http.Agent({ keepAlive: true }),
          httpsAgent: new https.Agent({ keepAlive: true }),
        }
      );

      const summary: string = response.data.summary;

      // حفظ الـ summary داخل فولدر الـ session
      const summaryPath = path.join(sessionFolder, "summary.txt");
      fs.writeFileSync(summaryPath, summary, "utf-8");

      return summary;
    } catch (error: any) {
      console.error("AI Service Error Details:", error.message);

      if (error.code === "ECONNABORTED") {
        throw new AppError(
          "AI service took too long to respond. Please try a smaller file.",
          504
        );
      }

      if (error.response) {
        throw new AppError(
          error.response.data.detail || "AI service error",
          error.response.status
        );
      } else if (error.code === "ECONNREFUSED") {
        throw new AppError(
          "AI service unavailable. Make sure Python server is running on port 8000.",
          503
        );
      } else {
        throw new AppError(`AI service error: ${error.message}`, 503);
      }
    }
  }

  /**
   * Ask a question about PDF
   */
  async askQuestion(
  sessionId: string,
  question: string
): Promise<{ messages: ChatMessage[] }> {

  if (!sessionId || !question) {
    throw new AppError("Missing sessionId or question", 400);
  }

  const sessionFolder = path.join("uploads", sessionId);
  if (!fs.existsSync(sessionFolder)) {
    throw new AppError("Session Folder Not Found", 404);
  }

  const chatFile = path.join(sessionFolder, "chat.json");

  let messages: ChatMessage[] = [];
  if (fs.existsSync(chatFile)) {
    const raw = JSON.parse(fs.readFileSync(chatFile, "utf-8"));
    messages = Array.isArray(raw) ? raw : [];
  }

  messages.push({ role: "user", content: question });

  let answer = "";
  let sources: { source: string; page: number }[] = [];

  try {

    const response = await axios.post(
      `${this.aiBaseUrl}/api/ask`,
      {sessionId, question},
      {
        headers: { 
          'Content-Type': 'application/json'
        },
        timeout: 600000,
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        httpAgent: new http.Agent({ keepAlive: true }),
        httpsAgent: new https.Agent({ keepAlive: true }),
      }
    );

    const aiData = response.data;

    answer = typeof aiData === "string" ? aiData : aiData.answer;
    sources = aiData?.sources ?? [];

  } catch (error: any) {
    if (error.response) {
      throw new AppError(
        error.response.data.detail || "AI service error",
        error.response.status
      );
    }
    throw new AppError("AI service unavailable", 503);
  }

  messages.push({
    role: "assistant",
    content: answer,
    sources
  });

  fs.writeFileSync(chatFile, JSON.stringify(messages, null, 2));

  return { messages };
}


  // الـ Handlers تظل كما هي لربطها بالـ Router
  aiSummarizeHandler = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    try {
      const { sessionId, filePath } = req.body;
      const summary = await this.summarize(sessionId, filePath);
      return res.status(200).json({ success: true, summary });
    } catch (error) {
      next(error);
    }
  };

  // aiAskQuestionHandler = async (req: Request, res: Response, next: NextFunction) => {
  //   try {
  //     const { sessionId, question } = req.body;
  //     const answer = await this.askQuestion(sessionId, question);
  //     return res.status(200).json({ success: true, answer });
  //   } catch (error) {
  //     next(error);
  //   }
  // };
}

export default new AiService();