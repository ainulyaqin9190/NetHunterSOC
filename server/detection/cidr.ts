/**
 * NetHunterSOC - IP and CIDR Matching Utility
 * Deterministic IPv4/IPv6 and CIDR network evaluation
 */

function ipv4ToLong(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const byte = Number(part);
    if (isNaN(byte) || byte < 0 || byte > 255) return null;
    num = (num << 8) + byte;
  }
  return num >>> 0; // Unsigned 32-bit integer
}

/**
 * Checks if a given IP matches an IP address or CIDR notation (e.g., "192.168.1.10", "192.168.1.0/24").
 */
export function ipMatchesCidrOrIp(targetIp: string, pattern: string): boolean {
  if (!targetIp || !pattern) return false;

  const cleanTarget = targetIp.trim().toLowerCase();
  const cleanPattern = pattern.trim().toLowerCase();

  // Exact match (IPv4 or IPv6 exact string)
  if (cleanTarget === cleanPattern) {
    return true;
  }

  // Check if pattern contains CIDR prefix
  if (cleanPattern.includes('/')) {
    const [network, prefixStr] = cleanPattern.split('/');
    const prefix = parseInt(prefixStr, 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

    const targetLong = ipv4ToLong(cleanTarget);
    const networkLong = ipv4ToLong(network);
    if (targetLong === null || networkLong === null) return false;

    if (prefix === 0) return true;
    const mask = prefix === 32 ? 0xffffffff : (~((1 << (32 - prefix)) - 1)) >>> 0;
    return (targetLong & mask) === (networkLong & mask);
  }

  return false;
}
