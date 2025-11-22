const cooldowns = new Map<string, number>();

const buildKey = (id: string, bucket: string): string => `${bucket}:${id}`;

export const hasCooldown = (id: string, bucket: string): boolean => {
  const key = buildKey(id, bucket);
  const now = Date.now();
  const expiresAt = cooldowns.get(key);

  if (expiresAt === undefined) {
    return false;
  }

  if (expiresAt <= now) {
    cooldowns.delete(key);
    return false;
  }

  return true;
};

export const addCooldown = (id: string, bucket: string, durationMs: number): void => {
  const key = buildKey(id, bucket);
  cooldowns.set(key, Date.now() + durationMs);
};
