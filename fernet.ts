import {
  aes,
  constantTimeCompare,
  createHmac,
  generateRandomIv,
  hex2uint,
  hex2urlsave,
  hexBits,
  parseHex,
  te,
  timeBytes,
  uint2hex,
  urlsave2hex,
} from "./utils.ts";

const VERSION_OFFSET = hexBits(8);
const TIME_OFFSET = VERSION_OFFSET + hexBits(64);
const IV_OFFSET = TIME_OFFSET + hexBits(128);
const HMAC_OFFSET = (tokenLength: number) => tokenLength - hexBits(256);

function encodeFernet(
  signKey: Uint8Array,
  encryptionKey: Uint8Array,
  msg: string,
  options?: { currentTime?: number; iv?: Uint8Array },
) {
  const version = (0x80).toString(16);
  const timestamp = timeBytes(options?.currentTime);
  const iv = typeof options?.iv !== "undefined"
    ? uint2hex(options.iv)
    : generateRandomIv();

  const ciphertext = aes.encrypt(
    encryptionKey,
    hex2uint(iv),
    te.encode(msg),
  );

  const hmac = createHmac(
    "sha256",
    signKey,
    `${version}${timestamp}${iv}${ciphertext}`,
  );

  return hex2urlsave(`${version}${timestamp}${iv}${ciphertext}${hmac}`);
}

function convertSecret(
  secret: string,
): {
  signKeyHex: string;
  encryptionKeyHex: string;
  signKeyUint: Uint8Array;
  encryptionKeyUint: Uint8Array;
} {
  secret = urlsave2hex(secret);
  if (secret.length !== hexBits(256)) {
    throw new Error("Secret must be 32 url-safe base64-encoded bytes.");
  }

  const signKeyHex = secret.slice(0, hexBits(128));
  const encryptionKeyHex = secret.slice(hexBits(128));

  return {
    signKeyHex,
    encryptionKeyHex,
    signKeyUint: hex2uint(signKeyHex),
    encryptionKeyUint: hex2uint(encryptionKeyHex),
  };
}

export function createSecret(size = 32) {
  return hex2urlsave(uint2hex(crypto.getRandomValues(new Uint8Array(size))));
}

function decodeFernet(
  signKey: Uint8Array,
  encryptionKey: Uint8Array,
  token: string,
  options?: { ttl?: number; maxClockSkew?: number; currentTime?: number },
) {
  const hexToken = urlsave2hex(token);
  if (hexToken.length < 146) {
    throw new Error("Invalid Token: To Short");
  }

  const version = parseHex(hexToken.slice(0, VERSION_OFFSET));

  if (version !== 128) {
    throw new Error("Invalid version");
  }

  const timestamp = parseHex(hexToken.slice(VERSION_OFFSET, TIME_OFFSET));

  if (options?.ttl && options.ttl > 0) {
    const now = (options?.currentTime ?? Date.now()) / 1000;

    if (now - timestamp > options.ttl) {
      throw new Error("Invalid Token: TTL");
    }

    if (now + (options?.maxClockSkew ?? 60) < timestamp) {
      throw new Error("Invalid Token: far-future timestamp");
    }
  }

  const iv = hexToken.slice(TIME_OFFSET, IV_OFFSET);
  const ciphertext = hexToken.slice(IV_OFFSET, HMAC_OFFSET(hexToken.length));
  const decodedHmac = hexToken.slice(HMAC_OFFSET(hexToken.length));
  const recomputedHmac = createHmac(
    "sha256",
    signKey,
    `${version.toString(16)}${timeBytes(timestamp * 1000)}${iv}${ciphertext}`,
  );

  if (!constantTimeCompare(recomputedHmac, decodedHmac)) {
    throw new Error("Invalid Token: HMAC");
  }

  return aes.decrypt(
    encryptionKey,
    hex2uint(iv),
    hex2uint(ciphertext),
  );
}

interface FernetOptions {
  ttl?: number;
  maxClockSkew?: number;
  secret?: string;
  currentTime?: number;
  iv?: Uint8Array;
}

export function createFernet(
  secret: string,
  options?: Pick<FernetOptions, "ttl" | "maxClockSkew">,
) {
  const keys = convertSecret(secret);
  return {
    ttl: options?.ttl,
    maxClockSkew: options?.maxClockSkew,
    signKeyUint: keys.signKeyUint,
    encryptionKeyUint: keys.encryptionKeyUint,

    encode(
      data: string,
      options?: Omit<FernetOptions, "ttl" | "maxClockSkew">,
    ) {
      const keys = options?.secret ? convertSecret(options.secret) : undefined;

      return encodeFernet(
        keys?.signKeyUint ?? this.signKeyUint,
        keys?.encryptionKeyUint ?? this.encryptionKeyUint,
        data,
        {
          currentTime: options?.currentTime,
          iv: options?.iv,
        },
      );
    },

    decode(
      token: string,
      options?: FernetOptions,
    ) {
      const keys = options?.secret ? convertSecret(options.secret) : undefined;

      return decodeFernet(
        keys?.signKeyUint ?? this.signKeyUint,
        keys?.encryptionKeyUint ?? this.encryptionKeyUint,
        token,
        {
          ttl: options?.ttl ?? this.ttl,
          maxClockSkew: options?.maxClockSkew ?? this.maxClockSkew,
          currentTime: options?.currentTime,
        },
      );
    },

    generateSecret(size?: number) {
      return createSecret(size);
    },

    setSecret(secret: string) {
      const keys = convertSecret(secret);
      this.signKeyUint = keys.signKeyUint;
      this.encryptionKeyUint = keys.encryptionKeyUint;
    },
  };
}

// TODO: Implement these errors:
/**
 * - too shord
 * - payload size not multiple of block size
 * - IMPORTANT: payload padding error
 * - IMPORTANT: invalid IV padding error
*/
