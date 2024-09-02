import { Request, Response } from "express";

import path from "path";
import fs from "fs";
import db from "../../lib/db";
import { PIN_GAME_TYPE } from "@prisma/client";

export const uploadFile = async (_req: Request, res: Response) => {
  try {
    return res
      .status(200)
      .json({ error: true, message: "File uploaded successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: true,
      message: `An error occurred while processing the file`,
    });
  }
};

export const uploadYaraRule = async (req: Request, res: Response) => {
  if (!req.file) {
    return res
      .status(400)
      .json({ error: true, message: "Please enter a valid file" });
  }

  if (!req.file.filename.endsWith(".yar")) {
    return res
      .status(400)
      .json({ error: true, message: "Please enter a valid yara rule" });
  }

  return res
    .status(200)
    .json({ error: false, message: "Yara rule updated successfully" });
};

export const sendFileByName = async (req: Request, res: Response) => {
  try {
    const { fileName } = req.body;

    if (!fileName)
      return res
        .status(400)
        .json({ error: true, message: "Please send a file name" });

    const fileDir = path.join(
      process.cwd(),
      "src",
      "dependencies",
      fileName.toString()
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

export const getUserConfig = async (req: Request, res: Response) => {
  try {
    const pin = await db.pin.findUnique({
      where: { pin: req.query.pin?.toString() },
    });

    const userConfig = await db.yaraRule.findFirst({
      where: {
        loaded: true,
        createdBy: pin?.userId,
        game: req.query.game?.toString().toUpperCase() as PIN_GAME_TYPE,
      },
    });

    const rule = userConfig?.rule;

    return res.status(200).send(rule);
  } catch {
    return res
      .status(500)
      .json({ error: true, message: "Error to load user config" });
  }
};
