import { type Request, Response } from "express";
import { checkIsValidPin } from "../services/auth.service";
import db from "../../lib/db";

export const startScan = async (req: Request, res: Response) => {
  try {
    const pin = req.query.pin;

    if (!pin) {
      return res
        .status(404)
        .json({ error: true, message: "Please enter a pin" });
    }

    const isValid = await checkIsValidPin(pin.toString());

    if (!isValid) {
      return res.status(400).json({ error: true, message: "Invalid pin" });
    }

    if (isValid.used) {
      return res.status(400).json({ error: true, message: "Pin already used" });
    }

    await db.pin.updateMany({
      where: { pin: pin.toString() },
      data: {
        used: true,
      },
    });

    return res
      .status(200)
      .json({ error: false, message: "Scan started successfully" });
  } catch (err) {
    console.log(err);
    return res
      .status(500)
      .json({ error: true, message: "Internal server error" });
  }
};

export const saveScanReuslt = async (req: Request, res: Response) => {
  try {
    const pin = req.query.pin;

    const { cheats, recentFiles, warnings } = req.body;

    await db.scanResult.create({
      data: {
        cheats: cheats,
        recentFiles: recentFiles,
        warnings: warnings,
        pin: pin?.toString() as string,
      },
      include: {
        recentFiles: true,
        cheats: true,
        warnings: true,
      },
    });

    if (!pin)
      return res
        .status(400)
        .json({ error: true, message: "Please send a pin" });

    if (typeof pin !== "string") {
      return res
        .status(400)
        .json({ error: true, message: "Invalid pin format" });
    }

    const isValid = await db.pin.findUnique({ where: { pin } });

    if (!isValid)
      return res.status(404).json({ error: true, message: "Pin not found" });

    return res.status(200).json({ error: false, message: "Results saved" });
  } catch {
    return res
      .status(500)
      .json({ error: true, message: "Internal server error" });
  }
};
