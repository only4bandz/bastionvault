// Registry of (mostly Canadian) card issuers. The domain drives the real logo
// (the bank's favicon); detection itself is fully local (see bins-ca.ts).
export interface Bank {
  id: string;
  name: string;
  domain: string;
}

export const BANKS: Record<string, Bank> = {
  cibc: { id: "cibc", name: "CIBC", domain: "cibc.com" },
  td: { id: "td", name: "TD", domain: "td.com" },
  rbc: { id: "rbc", name: "RBC", domain: "rbc.com" },
  bmo: { id: "bmo", name: "BMO", domain: "bmo.com" },
  scotiabank: { id: "scotiabank", name: "Scotiabank", domain: "scotiabank.com" },
  nbc: { id: "nbc", name: "National Bank", domain: "nbc.ca" },
  desjardins: { id: "desjardins", name: "Desjardins", domain: "desjardins.com" },
  tangerine: { id: "tangerine", name: "Tangerine", domain: "tangerine.ca" },
  simplii: { id: "simplii", name: "Simplii Financial", domain: "simplii.com" },
  canadiantire: { id: "canadiantire", name: "Canadian Tire Bank", domain: "canadiantire.ca" },
  pcfinancial: { id: "pcfinancial", name: "PC Financial", domain: "pcfinancial.ca" },
  laurentian: { id: "laurentian", name: "Laurentian Bank", domain: "laurentianbank.ca" },
  amex: { id: "amex", name: "American Express", domain: "americanexpress.com" },
  capitalone: { id: "capitalone", name: "Capital One", domain: "capitalone.ca" },
  walmart: { id: "walmart", name: "Walmart", domain: "walmart.ca" },
  mbna: { id: "mbna", name: "MBNA", domain: "mbna.ca" },
  wealthsimple: { id: "wealthsimple", name: "Wealthsimple", domain: "wealthsimple.com" },
  koho: { id: "koho", name: "KOHO", domain: "koho.ca" },
  neo: { id: "neo", name: "Neo Financial", domain: "neofinancial.com" },
};
