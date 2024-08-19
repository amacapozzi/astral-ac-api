import { type Request, Response } from "express";
import {
  checkIsValidPin,
  determineScanResultType,
} from "../services/auth.service";
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

export const saveScanResult = async (req: Request, res: Response) => {
  try {
    const pin = req.query.pin as string;

    if (!pin) {
      return res
        .status(400)
        .json({ error: true, message: "Please send a pin" });
    }

    if (typeof pin !== "string") {
      return res
        .status(400)
        .json({ error: true, message: "Invalid pin format" });
    }

    const isValid = await db.pin.findUnique({ where: { pin } });

    if (!isValid) {
      return res.status(404).json({ error: true, message: "Pin not found" });
    }

    const {
      cheats,
      recentFiles,
      warnings,
      username,
      hwid,
      discord,
      scanTime,
      installDate,
    } = req.body;

    if (!username || !hwid || !discord) {
      return res
        .status(400)
        .json({ error: true, message: "Missing required fields" });
    }

    const existingDiscordUser = await db.discordUser.findFirst({
      where: { discordId: discord.discordId },
    });

    const discordUserData = existingDiscordUser
      ? existingDiscordUser
      : await db.discordUser.create({ data: discord });

    const createdCheats = await Promise.all(
      cheats.map(async (cheat: any) => {
        return await db.cheats.create({ data: cheat });
      })
    );

    const createdRecentFiles = await Promise.all(
      recentFiles.map(async (file: any) => {
        return await db.recentFiles.create({ data: file });
      })
    );

    const createdWarnings = await Promise.all(
      warnings.map(async (warning: any) => {
        return await db.warnings.create({ data: warning });
      })
    );

    const type = determineScanResultType(warnings.length, cheats.length);

    const scanResult = await db.scanResult.create({
      data: {
        username,
        hwid,
        installDate,
        type,
        cheats: {
          connect: createdCheats.map((cheat) => ({ id: cheat.id })),
        },
        recentFiles: {
          connect: createdRecentFiles.map((file) => ({ id: file.id })),
        },
        warnings: {
          connect: createdWarnings.map((warning) => ({ id: warning.id })),
        },
        pin: {
          connect: { id: isValid.id },
        },
        discordUser: {
          connect: { id: discordUserData.id },
        },
      },
      include: {
        recentFiles: true,
        cheats: true,
        warnings: true,
        discordUser: true,
      },
    });

    await db.pin.update({
      where: { id: isValid.id },
      data: {
        used: true,
        scanned: true,
        scanDuration: scanTime,
        scanResult: { connect: { id: scanResult.id } },
      },
      include: { scanResult: true },
    });

    return res.status(200).json({ error: false, message: "Results saved" });
  } catch (err) {
    console.log(err);
    return res
      .status(500)
      .json({ error: true, message: "Internal server error" });
  }
};
