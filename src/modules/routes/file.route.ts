import express from "express";
import multer from "multer";
import {
  getUserConfig,
  sendFileByName,
  uploadFile,
} from "../controllers/file.controller";
import { cliMiddleware } from "../middleware/cli.midleware";
import { getFilePathByType } from "../../utils/fileType";

const storage = multer.diskStorage({
  destination: "src/dependencies",
  filename: function (req, file, callback) {
    const { fileType, game } = req.body;
    const name = getFilePathByType(
      fileType?.toString().toUpperCase(),
      game,
      file.originalname
    );
    callback(null, name?.toString() as string);
  },
});
const upload = multer({
  storage: storage,
  limits: { fileSize: Infinity, fieldSize: Infinity },
});

export const fileRouter = express.Router();

fileRouter.route("/download").get(cliMiddleware, sendFileByName);
fileRouter.route("/getRule").get(cliMiddleware, getUserConfig);
fileRouter
  .route("/upload")
  .post(cliMiddleware, upload.single("file"), uploadFile);
