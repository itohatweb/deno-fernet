import {
  Aes,
  base64url,
  Cbc,
  hmac,
  Padding,
  SupportedAlgorithm,
} from "./deps.ts";

export const td = new TextDecoder();
export const te = new TextEncoder();

/** Convert a hex string to url save base64. */
export function hex2urlsave(hex: string) {
  const conv = base64url.encode(hex2uint(hex));

  return conv.padEnd(conv.length + 4 - (conv.length % 4), "=");
}

/** Convert a url save base64 to a hex. */
export function urlsave2hex(urlsave: string) {
  return uint2hex(base64url.decode(urlsave));
}

/** Convert a UNIX timestamp to the correct format for a fernet token. */
export function timeBytes(time?: number) {
  if (time) {
    time = Math.round(time / 1000);
  } else {
    time = Math.round(Date.now() / 1000);
  }

  return time.toString(16).padStart(16, "0");
}

/** Generate a random IV for AES CBC. */
export function generateRandomIv(size = 16) {
  return uint2hex(crypto.getRandomValues(new Uint8Array(size)));
}

/** Convert an Uint8Array to a hex string. */
export function uint2hex(uint: Uint8Array) {
  return [...uint].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Convert a hex string to an Uint8Array. */
export function hex2uint(hex: string) {
  if (hex.length % 2 || !/^[A-Fa-f\d+]+$/.test(hex)) {
    throw new Error("Invalid hex string.");
  }
  return new Uint8Array(
    hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
  );
}

/** Get the hex length for these bits. */
export function hexBits(bits: number) {
  return (bits / 8) * 2;
}

/** Parse a hex to an int. */
export function parseHex(hex: string) {
  return parseInt(`0x${hex}`);
}

/** Constant time compare two strings. */
export function constantTimeCompare(a: string, b: string) {
  let result = 0;

  if (a.length !== b.length) {
    b = a;
    result = 1;
  }

  for (let i = 0, len = a.length; i < len; ++i) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

function encrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): string {
  const cipher = new Cbc(Aes, key, iv, Padding.PKCS7);
  return uint2hex(cipher.encrypt(data));
}

function decrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): string {
  const decipher = new Cbc(Aes, key, iv, Padding.PKCS7);
  return td.decode(decipher.decrypt(data));
}

export const aes = { encrypt, decrypt };

export function createHmac(
  hash: SupportedAlgorithm,
  key: Uint8Array,
  hexData: string,
): string {
  return uint2hex(hmac(hash, key, hex2uint(hexData)));
}
