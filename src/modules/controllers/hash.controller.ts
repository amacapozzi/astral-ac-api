import { type Request, Response } from "express";
import db from "../../lib/db";

interface ExtractedData {
  clientName: string;
  clientHash: string;
  processName: string;
  severity: string;
}

const extractRelevantData = (data: any[]): ExtractedData[] => {
  return data.map((item) => ({
    clientName: item.clientName,
    clientHash: item.clientHash,
    processName: item.processName,
    severity: item.severity,
  }));
};

export const getHashes = async (req: Request, res: Response) => {
  const game = req.query.game;

  if (!game) {
    return res
      .status(400)
      .json({ error: true, message: "Please enter a game" });
  }

  let gameHashes;

  if (game.toString().toUpperCase() === "MINECRAFT") {
    gameHashes = await db.clientStrings.findMany({
      where: { game: "MINECRAFT" },
    });
  } else if (game.toString().toUpperCase() === "FIVEM") {
    gameHashes = await db.clientStrings.findMany({
      where: { game: "FIVEM" },
    });
  } else {
    return res.status(404).json({ error: true, message: "Invalid game" });
  }

  const relevantData = extractRelevantData(gameHashes);
  return res.status(200).json(relevantData);
};
