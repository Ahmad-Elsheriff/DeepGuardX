import { Request, Response, NextFunction } from "express";
import { execFile } from "child_process";
import path from "path";
import fs from "fs";

class CyberService {
  // Core scan function
  async scan(sessionId: string, filePath: string): Promise<any> {
    return new Promise((resolve, reject) => {
      // Ensure session folder exists
      const sessionFolder = path.join("uploads", sessionId);
      if (!fs.existsSync(sessionFolder)) {
        fs.mkdirSync(sessionFolder, { recursive: true });
      }

      const pythonScript = path.resolve("pdf-security-scanner/gate.py");
      const pdfFullPath = path.resolve(filePath);

      // Call Python gate.py
      const pythonPath = "C:\\Users\\ahmad\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
      execFile(
        pythonPath,
        [pythonScript, pdfFullPath, sessionId],
        { cwd: process.cwd() },
        (error, stdout, stderr) => {
          if (error) {
            console.error("Error running Python scanner:", error);
            reject(error);
          } else {
            console.log(stdout);

            const reportFile = pdfFullPath + ".report.json";
            if (fs.existsSync(reportFile)) {
              const reportData = JSON.parse(
                fs.readFileSync(reportFile, "utf-8")
              );

              // Move report to session folder
              const destPath = path.join(
                sessionFolder,
                path.basename(reportFile)
              );
              fs.renameSync(reportFile, destPath);

              resolve(reportData); // Return report JSON
            } else {
              reject(new Error("Report JSON not generated"));
            }
          }
        }
      );
    });
  }

  // Express route handler for uploads
  scanFile = async (req: Request, res: Response, next: NextFunction) => {
    const { sessionId, filePath } = req.body;

    try {
      const report = await this.scan(sessionId, filePath);
      return res.status(200).json(report);
    } catch (err: any) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };
}

export default new CyberService();
