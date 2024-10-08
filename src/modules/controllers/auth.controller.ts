import { type Request, Response } from "express";
import {
  checkIsValidPin,
  determineScanResultType,
} from "../services/auth.service";
import db from "../../lib/db";
import { isAutoSelf } from "../../utils/security";

export const startScan = async (req: Request, res: Response) => {
  try {
    const pin = req.query.pin;
    const queryFrom = req.query.queryFrom;

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

    const autoSelf = await isAutoSelf(
      isValid.scanResult?.hwid as string,
      isValid?.scannedAt as Date
    );

    if (autoSelf) {
      return res
        .status(400)
        .json({ error: true, message: "Auto self scan detected" });
    }

    const changeTrue = queryFrom == "page" ? false : true;

    await db.pin.updateMany({
      where: { pin: pin.toString() },
      data: {
        used: changeTrue,
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
      recordingSoftwares,
      recentFiles,
      warnings,
      username,
      hwid,
      discord,
      scanTime,
      steamAccounts,
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

    const recordSoftwares = await Promise.all(
      recordingSoftwares.map(async (file: any) => {
        return await db.recordingSoftwares.create({ data: file });
      })
    );
    const steamAccountsMapped = await Promise.all(
      steamAccounts.map(async (acc: any) => {
        return await db.steamAccounts.create({ data: acc });
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
        recordingSoftwares: {
          connect: recordSoftwares.map((software) => ({ id: software.id })),
        },
        steamAccounts: {
          connect: steamAccountsMapped.map((account) => ({ id: account.id })),
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
        scannedAt: new Date(),
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
