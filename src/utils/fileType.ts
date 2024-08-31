import { PIN_GAME_TYPE } from "@prisma/client";
import { FileType } from "../types/Structs";

export const getFilePathByType = (
  fileType: FileType,
  game: PIN_GAME_TYPE,
  fileName?: string
) => {
  switch (fileType) {
    case "DEPENDENCIE":
      return fileName;
    case "CLI":
      return `${game.toLowerCase()}-cli.exe`;
    case "GUI":
      return `${game.toLowerCase()}-gui.exe`;
  }
};
