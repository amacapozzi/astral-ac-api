import db from "../../lib/db";

export const checkIsValidPin = async (pin: string) => {
  const isExists = await db.pin.findUnique({
    where: { pin },
    include: { scanResult: true },
  });
  return isExists;
};

type ScanResultType = "SUSPICIOUS" | "LEGIT" | "CHEATER";

export const determineScanResultType = (
  warningsCount: number,
  cheatsCount: number
): ScanResultType => {
  if (cheatsCount > 0) {
    return "CHEATER";
  }
  if (warningsCount > 3) {
    return "SUSPICIOUS";
  }
  return "LEGIT";
};
