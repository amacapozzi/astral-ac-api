import db from ".././lib/db";

export const isAutoSelf = async (
  hwid: string,
  lastScannedAt: Date
): Promise<boolean> => {
  try {
    const userHistoryPins = await db.scanResult.findMany({
      where: { hwid },
      include: { pin: true },
    });

    const fiveHoursAgo = new Date(lastScannedAt.getTime() - 5 * 60 * 60 * 1000);

    const recentScans = userHistoryPins.filter((userHistory) => {
      return (userHistory?.pin?.scannedAt as Date) > fiveHoursAgo;
    });

    return recentScans.length >= 2;
  } catch (error) {
    console.error(error);
    return false;
  }
};
