export interface VaccineConfig {
  vaccineEnabled: boolean;
  vaccineDeleteMalicious: boolean;
  vaccineThreshold: number;
  virusTotalApiKey: string | null;
}

export interface EnvConfig {
  vaccine: VaccineConfig;
}

const parseBoolean = (value: string | undefined, defaultValue: boolean): boolean => {
  if (value === undefined) {
    return defaultValue;
  }

  return value.toLowerCase() === 'true';
};

const parseNumber = (value: string | undefined, defaultValue: number): number => {
  if (value === undefined) {
    return defaultValue;
  }

  const parsed = Number(value);
  return Number.isNaN(parsed) ? defaultValue : parsed;
};

export const env: EnvConfig = {
  vaccine: {
    vaccineEnabled: parseBoolean(process.env.VACCINE_ENABLED, true),
    vaccineDeleteMalicious: parseBoolean(process.env.VACCINE_DELETE_MALICIOUS, false),
    vaccineThreshold: parseNumber(process.env.VACCINE_THRESHOLD, 2),
    virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY ?? null
  }
};
