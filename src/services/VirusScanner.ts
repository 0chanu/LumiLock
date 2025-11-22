import crypto from 'node:crypto';
import axios, { AxiosInstance } from 'axios';
import FormData from 'form-data';
import PQueue from 'p-queue';

export interface VirusTotalAnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
  [key: string]: number;
}

export interface VirusScanResult {
  sha256: string;
  positives: number;
  total: number;
  stats: VirusTotalAnalysisStats;
  permalink?: string;
}

const queue = new PQueue({
  interval: 15000,
  intervalCap: 1
});

const DOWNLOAD_TIMEOUT_MS = 15_000;
const MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024;

export class VirusScanner {
  private readonly apiKey: string;
  private readonly client: AxiosInstance;

  public constructor(apiKey: string) {
    this.apiKey = apiKey;
    this.client = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      headers: {
        'x-apikey': this.apiKey
      },
      timeout: 30000
    });
  }

  public async scanFileFromUrl(url: string, filename: string): Promise<VirusScanResult | null> {
    try {
      const fileBuffer = await this.downloadFile(url);
      const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

      const existing = await this.getReport(sha256);
      if (existing) {
        return existing;
      }

      const analysisId = await this.uploadFile(fileBuffer, filename);
      if (!analysisId) {
        return null;
      }

      const result = await this.pollAnalysisResult(analysisId, sha256);
      return result;
    } catch (error) {
      console.error('[VirusScanner] scanFileFromUrl error:', error);
      return null;
    }
  }

  private async getReport(sha256: string): Promise<VirusScanResult | null> {
    const result = await queue.add(async (): Promise<VirusScanResult | null> => {
      try {
        const response = await this.client.get(`/files/${sha256}`);
        const data = response.data?.data;
        if (!data?.attributes?.last_analysis_stats) {
          return null;
        }

        const stats: VirusTotalAnalysisStats = data.attributes.last_analysis_stats;
        const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
        const total =
          (stats.harmless ?? 0) +
          (stats.malicious ?? 0) +
          (stats.suspicious ?? 0) +
          (stats.undetected ?? 0) +
          (stats.timeout ?? 0);

        return {
          sha256,
          positives,
          total,
          stats,
          permalink: `https://www.virustotal.com/gui/file/${sha256}/detection`
        };
      } catch (error: unknown) {
        if (axios.isAxiosError(error) && error.response?.status === 404) {
          return null;
        }

        console.error('[VirusScanner] getReport error:', error);
        return null;
      }
    });

    return result ?? null;
  }

  private async uploadFile(buffer: Buffer, filename: string): Promise<string | null> {
    const analysisId = await queue.add(async (): Promise<string | null> => {
      try {
        const form = new FormData();
        form.append('file', buffer, { filename });

        const response = await this.client.post('/files', form, {
          headers: form.getHeaders(),
          maxBodyLength: Infinity
        });

        const id: string | undefined = response.data?.data?.id;
        return id ?? null;
      } catch (error) {
        console.error('[VirusScanner] uploadFile error:', error);
        return null;
      }
    });

    return analysisId ?? null;
  }

  private async pollAnalysisResult(analysisId: string, sha256: string): Promise<VirusScanResult | null> {
    const maxAttempts = 12;
    const delayMs = 15000;

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      console.log('[VirusScanner] polling analysis status', {
        analysisId,
        attempt: attempt + 1,
        maxAttempts
      });

      await new Promise((resolve) => setTimeout(resolve, delayMs));

      const result = await queue.add(async (): Promise<VirusScanResult | null> => {
        try {
          const response = await this.client.get(`/analyses/${analysisId}`);
          const data = response.data?.data;

          if (data?.attributes?.status !== 'completed') {
            return null;
          }

          const stats: VirusTotalAnalysisStats | undefined = data.attributes.stats;
          if (!stats) {
            return null;
          }

          const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
          const total =
            (stats.harmless ?? 0) +
            (stats.malicious ?? 0) +
            (stats.suspicious ?? 0) +
            (stats.undetected ?? 0) +
            (stats.timeout ?? 0);

          return {
            sha256,
            positives,
            total,
            stats,
            permalink: `https://www.virustotal.com/gui/file/${sha256}/detection`
          };
        } catch (error) {
          console.error('[VirusScanner] pollAnalysisResult error:', error);
          return null;
        }
      });

      if (result) {
        return result;
      }
    }

    return null;
  }

  private async downloadFile(url: string): Promise<Buffer> {
    const response = await axios.get<ArrayBuffer>(url, {
      responseType: 'arraybuffer',
      timeout: DOWNLOAD_TIMEOUT_MS,
      maxContentLength: MAX_DOWNLOAD_BYTES,
      maxBodyLength: MAX_DOWNLOAD_BYTES,
      validateStatus: (status) => status >= 200 && status < 400
    });

    return Buffer.from(response.data);
  }
}
