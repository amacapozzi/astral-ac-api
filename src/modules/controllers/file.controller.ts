import { Request, Response } from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    const uploadPath = path.join(process.cwd(), "src", "uploads");

    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (_req, file, cb) => {
    cb(null, file.originalname);
  },
});

export const upload = multer({ storage });

function getFormattedLinkerTime(filePath: string) {
  if (!fs.existsSync(filePath)) {
    throw new Error("File not found");
  }

  const validExtensions = [".exe", ".dll"];

  const fileExtension = filePath.slice(-4).toLowerCase();
  if (!validExtensions.some((ext) => ext === fileExtension)) {
    throw new Error("Invalid file extension");
  }

  const c_PeHeaderOffset = 60;
  const c_LinkerTimestampOffset = 8;
  const buffer = Buffer.alloc(2048);

  const fd = fs.openSync(filePath, "r");
  fs.readSync(fd, buffer, 0, 2048, 0);
  fs.closeSync(fd);

  const offset = buffer.readUInt32LE(c_PeHeaderOffset);
  const timestamp = buffer.readUInt32LE(offset + c_LinkerTimestampOffset);
  const date = new Date(timestamp * 1000);
  const formattedTimestamp = date.toISOString().replace("T", ":").slice(0, 19);

  return formattedTimestamp;
}

async function calculateHashes(filePath: string) {
  try {
    const fileInfo = await getFormattedLinkerTime(filePath);

    const defaultFileInfo = fs.readFileSync(filePath);
    const fileStream = fs.createReadStream(filePath);

    const md5Hash = crypto.createHash("md5");
    fileStream.on("data", (data) => {
      md5Hash.update(data);
    });

    const sha256Hash = crypto.createHash("sha256");
    fileStream.on("data", (data) => {
      sha256Hash.update(data);
    });

    await new Promise((resolve, reject) => {
      fileStream.on("end", () => {
        resolve(true);
      });
      fileStream.on("error", (err) => {
        reject(err);
      });
    });

    const md5Digest = md5Hash.digest("hex");
    const sha256Digest = sha256Hash.digest("hex");

    return {
      md5: md5Digest,
      size: defaultFileInfo.length,
      sha256: sha256Digest,
      fileInfo: `!${fileInfo.toString().replace("-", ":")}!`,
    };
  } catch (error) {
    console.error(error);
    return {
      error: true,
      message: `An error occurred while processing the file`,
    };
  }
}

export const uploadFile = async (
  req: Request,
  res: Response
): Promise<Response> => {
  if (!req.file) {
    return res
      .status(400)
      .json({ error: true, message: "Please upload a file" });
  }

  const filePath = req.file.path;

  try {
    const fileInfo = await calculateHashes(filePath);

    return res.status(200).json({ data: fileInfo });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: true,
      message: `An error occurred while processing the file`,
    });
  }
};
export const sendFileByName = async (req: Request, res: Response) => {
  try {
    const { file } = req.query;

    if (!file)
      return res
        .status(400)
        .json({ error: true, message: "Please send a file name" });

    const fileDir = path.join(
      process.cwd(),
      "src",
      "dependencies",
      file.toString() + ".exe"
    );

    if (!fs.existsSync(fileDir)) {
      return res.status(404).json({ error: true, message: "File not found" });
    }

    return res.download(fileDir);
  } catch {
    return res.status(500).json({
      error: true,
      message: "An error occurred while sending the dependency",
    });
  }
};
