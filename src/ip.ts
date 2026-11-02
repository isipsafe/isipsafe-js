const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIPv4(value: string): boolean {
  return IPV4.test(value);
}

export function isIPv6(value: string): boolean {
  if (!value.includes(':') || /[^0-9a-fA-F:.]/.test(value)) return false;
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

export function isIP(value: string): boolean {
  return isIPv4(value) || isIPv6(value);
}

export function isCidr(value: string): boolean {
  const [address, prefix, ...rest] = value.split('/');
  if (rest.length || address === undefined || prefix === undefined || !/^\d{1,3}$/.test(prefix)) return false;
  const bits = Number(prefix);
  if (isIPv4(address)) return bits <= 32;
  if (isIPv6(address)) return bits <= 128;
  return false;
}

export function assertIP(value: string): string {
  const ip = String(value).trim();
  if (!isIP(ip)) throw new TypeError(`not a valid IPv4 or IPv6 address: ${JSON.stringify(value)}`);
  return ip;
}

export function assertIPOrCidr(value: string): string {
  const ip = String(value).trim();
  if (!isIP(ip) && !isCidr(ip)) throw new TypeError(`not a valid IP address or CIDR network: ${JSON.stringify(value)}`);
  return ip;
}

export function assertCidr(value: string): string {
  const net = String(value).trim();
  if (!isCidr(net)) throw new TypeError(`not a valid CIDR network: ${JSON.stringify(value)}`);
  return net;
}
