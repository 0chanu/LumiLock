import { DiscordAPIError, Events, Message, type Attachment, type TopLevelComponentData } from 'discord.js';
import { ButtonStyle, ComponentType, MessageFlags } from 'discord-api-types/v10';
import { env } from '../config/env';
import { VirusScanner, type VirusScanResult } from '../services/VirusScanner';
import { addCooldown, hasCooldown } from '../utils/cooldown';

const COOLDOWN_BUCKET = 'vaccine';
const BASE_COOLDOWN_MS = 30_000;
const MAX_SCAN_SIZE_BYTES = 32 * 1024 * 1024;
const SCANNABLE_EXTENSIONS = new Set([
  'exe',
  'dll',
  'msi',
  'bat',
  'cmd',
  'sh',
  'ps1',
  'js',
  'jar',
  'com',
  'scr',
  'vbs',
  'ws',
  'msp',
  'apk',
  'dmg',
  'pkg',
  'app',
  'iso',
  'img',
  'zip',
  'rar',
  '7z',
  'tar',
  'gz',
  'bz2',
  'xz',
  'docm',
  'xlsm',
  'pptm'
]);

let loggedDisabled = false;
let loggedMissingApiKey = false;

const scanner =
  env.vaccine.virusTotalApiKey !== null
    ? new VirusScanner(env.vaccine.virusTotalApiKey)
    : null;

export default {
  name: Events.MessageCreate,
  async execute(message: Message): Promise<void> {
    if (!env.vaccine.vaccineEnabled) {
      if (!loggedDisabled) {
        console.warn('[vaccine] disabled via VACCINE_ENABLED=false');
        loggedDisabled = true;
      }
      return;
    }

    if (message.author.bot) {
      return;
    }

    if (message.channel.isDMBased?.()) {
      return;
    }

    if (!scanner) {
      if (!loggedMissingApiKey) {
        console.warn('[vaccine] missing VIRUSTOTAL_API_KEY - skipping scans');
        loggedMissingApiKey = true;
      }
      return;
    }

    const urlsInMessage = extractUrls(message.content);
    const scannableUrls = urlsInMessage.filter(isScannableUrl);

    if (message.attachments.size === 0 && scannableUrls.length === 0) {
      return;
    }

    if (hasCooldown(message.author.id, COOLDOWN_BUCKET)) {
      return;
    }

    const totalAttachmentBytes = Array.from(message.attachments.values()).reduce(
      (sum, attachment) => sum + (attachment.size ?? 0),
      0
    );
    const dynamicCooldown =
      BASE_COOLDOWN_MS +
      Math.min(60_000, Math.ceil(totalAttachmentBytes / (5 * 1024 * 1024)) * 5_000);
    addCooldown(message.author.id, COOLDOWN_BUCKET, dynamicCooldown);

    const tasks: Array<Promise<void>> = [];
    for (const attachment of message.attachments.values()) {
      tasks.push(scanAttachment(message, attachment));
    }
    for (const url of scannableUrls) {
      tasks.push(scanUrl(message, url));
    }

    // 비동기 처리로 메시지 핸들러를 오래 점유하지 않음
    void Promise.allSettled(tasks);
  }
};

const scanAttachment = async (message: Message, attachment: Attachment): Promise<void> => {
  if (attachment.size > MAX_SCAN_SIZE_BYTES) {
    console.info('[vaccine] skipped (too large)', {
      attachment: attachment.name,
      size: attachment.size,
      messageId: message.id
    });
    return;
  }

  if (!attachment.url) {
    console.info('[vaccine] skipped (no url)', {
      attachment: attachment.name,
      messageId: message.id
    });
    return;
  }

  const extension = attachment.name?.split('.').pop()?.toLowerCase();
  if (extension && !SCANNABLE_EXTENSIONS.has(extension)) {
    console.info('[vaccine] skipped (non-scannable type)', {
      attachment: attachment.name,
      extension,
      messageId: message.id
    });
    return;
  }

  try {
    console.log('[vaccine] scanning attachment', {
      attachment: attachment.name,
      size: attachment.size,
      messageId: message.id
    });

    const result = await scanner?.scanFileFromUrl(
      attachment.url,
      attachment.name ?? 'attachment'
    );
    if (!result) {
      console.log('[vaccine] scan skipped (no result)', {
        attachment: attachment.name,
        messageId: message.id
      });
      return;
    }

    if (result.positives >= env.vaccine.vaccineThreshold) {
      console.warn('[vaccine] malicious file detected', {
        attachment: attachment.name,
        positives: result.positives,
        total: result.total,
        threshold: env.vaccine.vaccineThreshold,
        messageId: message.id
      });

      const vtLink =
        result.permalink ?? `https://www.virustotal.com/gui/file/${result.sha256}/detection`;

      const alertComponents = buildAlertComponents(attachment.name ?? 'attachment', vtLink, result);

      await message.reply({
        flags: MessageFlags.IsComponentsV2,
        components: alertComponents,
        allowedMentions: { repliedUser: false },
        content: ' ' // v2 컴포넌트만 있는 메시지가 숨김 처리되지 않도록 최소 콘텐츠 유지
      });

      if (env.vaccine.vaccineDeleteMalicious) {
        await message.delete().catch((error) => {
          if (error instanceof DiscordAPIError && error.code === 50013) {
            console.error('[vaccine] failed to delete message (missing permissions)', {
              messageId: message.id
            });
            return;
          }
          console.error('[vaccine] failed to delete message:', error);
        });
      }
    } else {
      console.log('[vaccine] file considered safe', {
        attachment: attachment.name,
        positives: result.positives,
        total: result.total,
        threshold: env.vaccine.vaccineThreshold,
        messageId: message.id
      });
    }
  } catch (error) {
    console.error('[vaccine] error while scanning attachment:', error);
  }
};


const scanUrl = async (message: Message, url: string): Promise<void> => {
  try {
    const filename = getFilenameFromUrl(url) ?? 'download';
    console.log('[vaccine] scanning url', { url, filename, messageId: message.id });

    const result = await scanner?.scanFileFromUrl(url, filename);
    if (!result) {
      console.log('[vaccine] scan skipped (no result)', { url, messageId: message.id });
      return;
    }

    if (result.positives >= env.vaccine.vaccineThreshold) {
      console.warn('[vaccine] malicious url detected', {
        url,
        positives: result.positives,
        total: result.total,
        threshold: env.vaccine.vaccineThreshold,
        messageId: message.id
      });

      const vtLink =
        result.permalink ?? `https://www.virustotal.com/gui/file/${result.sha256}/detection`;
      const alertComponents = buildAlertComponents(filename, vtLink, result, url);

      await message.reply({
        flags: MessageFlags.IsComponentsV2,
        components: alertComponents,
        allowedMentions: { repliedUser: false },
        content: ' '
      });

      if (env.vaccine.vaccineDeleteMalicious) {
        await message.delete().catch((error) => {
          if (error instanceof DiscordAPIError && error.code === 50013) {
            console.error('[vaccine] failed to delete message (missing permissions)', {
              messageId: message.id
            });
            return;
          }
          console.error('[vaccine] failed to delete message:', error);
        });
      }
    } else {
      console.log('[vaccine] url considered safe', {
        url,
        positives: result.positives,
        total: result.total,
        threshold: env.vaccine.vaccineThreshold,
        messageId: message.id
      });
    }
  } catch (error) {
    console.error('[vaccine] error while scanning url:', error);
  }
};


const buildAlertComponents = (
  filename: string,
  vtLink: string,
  result: VirusScanResult,
  url?: string
): TopLevelComponentData[] => {
  const sha256 = result.sha256 ?? '알 수 없음';

  const lines = [
    { type: ComponentType.TextDisplay, content: '`🚨` 악성 파일 감지' },
    { type: ComponentType.TextDisplay, content: `파일명: ${filename}` },
    ...(url ? [{ type: ComponentType.TextDisplay, content: `링크: ${url}` }] : []),
    {
      type: ComponentType.TextDisplay,
      content: `탐지율: ${result.positives}/${result.total} (기준 ${env.vaccine.vaccineThreshold}+ 엔진)`
    },
    { type: ComponentType.TextDisplay, content: `SHA256: ${sha256}` },
    {
      type: ComponentType.TextDisplay,
      content: '조치: 파일 실행·공유를 중단하고 관리자에게 알리세요.'
    }
  ];

  // Section 컴포넌트는 자식이 1~3개만 허용되므로 3개씩 나눠 담는다.
  const sections: Array<{
    type: ComponentType.Section;
    components: typeof lines;
    accessory?: {
      type: ComponentType.Button;
      style: ButtonStyle.Link;
      label: string;
      url: string;
    };
  }> = [];
  for (let i = 0; i < lines.length; i += 3) {
    sections.push({
      type: ComponentType.Section,
      components: lines.slice(i, i + 3)
    });
  }

  // 모든 섹션에 VT 링크 버튼을 단다 (accessory 필드 필수 요구 대응).
  sections.forEach((section) => {
    section.accessory = {
      type: ComponentType.Button,
      style: ButtonStyle.Link,
      label: 'VT 결과 열기',
      url: vtLink
    };
  });

  return [
    {
      type: ComponentType.Container,
      components: sections
    }
  ];
};
const extractUrls = (text: string): string[] => {
  if (!text) return [];
  const urlRegex = /(https?:\/\/[^\s<>"]+)/gi;
  const matches = text.match(urlRegex) ?? [];
  return Array.from(new Set(matches));
};

const isScannableUrl = (url: string): boolean => {
  const ext = getExtensionFromUrl(url);
  return ext ? SCANNABLE_EXTENSIONS.has(ext) : false;
};

const getExtensionFromUrl = (url: string): string | null => {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname.split('/').pop() ?? '';
    const ext = pathname.split('.').pop()?.toLowerCase();
    if (!ext || ext === pathname) {
      return null;
    }
    return ext;
  } catch {
    return null;
  }
};

const getFilenameFromUrl = (url: string): string | null => {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname.split('/').pop();
    if (pathname && pathname.trim().length > 0) {
      return decodeURIComponent(pathname);
    }
    return null;
  } catch {
    return null;
  }
};
