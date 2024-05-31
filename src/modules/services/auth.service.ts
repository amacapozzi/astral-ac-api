import db from "../../lib/db";

export const checkIsValidPin = async (pin: string) => {
  const isExists = await db.pin.findUnique({ where: { pin } });
  return isExists;
};
