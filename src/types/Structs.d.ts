export type Cheat = {
  clientName: string;
  clientDir: string;
  inInstance: boolean;
  clientType: "DETECT" | "WARNING";
};

export type RecentFile = {
  path: string;
  openDate: string;
  isSigned: boolean;
};

export type Warning = {
  name: string;
  description: string;
};
