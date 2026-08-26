// dsh-remote-gateway — self-signed TLS certificate generation in pure Node.
//
// No openssl dependency: `node:crypto` generates the RSA key pair and signs,
// and a minimal X.509 v3 DER encoder builds the certificate, so
// `dsh-web-auth gen-cert` works on any platform (Windows included, where
// openssl is usually absent from PATH).
//
// The output mirrors what `openssl req -x509` produced before:
//   - RSA 2048, SHA-256 signature
//   - CN=DeepSeek Harness Web (subject == issuer, self-signed)
//   - SANs: DNS + IP entries (the CLI feeds localhost + LAN addresses)
//   - basicConstraints CA:true (critical) so the cert can be imported into
//     an OS/browser trust store and trusted directly
//   - keyUsage digitalSignature+keyEncipherment, extKeyUsage serverAuth
import { createSign, createVerify, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { networkInterfaces } from "node:os";
import { dirname } from "node:path";

// ── minimal DER encoding ────────────────────────────────────────────────────

/** DER length octets for a content of `length` bytes. */
function derLen(length) {
  if (length < 0x80) return [length];
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

/** TLV: tag byte + DER length + content. */
function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag, ...derLen(content.length)]), content]);
}

/** Content bytes of a positive INTEGER (strip leading zeros, add sign byte). */
function integerBytes(value) {
  let bytes = value;
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if ((bytes[0] & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  return bytes;
}

/** DER-encoded OBJECT IDENTIFIER from dotted components. */
function oidBytes(...components) {
  const out = [40 * components[0] + components[1]];
  for (const component of components.slice(2)) {
    let value = component;
    const group = [value & 0x7f];
    value >>>= 7;
    while (value > 0) {
      group.unshift((value & 0x7f) | 0x80);
      value >>>= 7;
    }
    out.push(...group);
  }
  return Buffer.from(out);
}

/** PEM-wrap a DER blob (64-column base64). */
function pem(label, der) {
  const b64 = der.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

// ── X.509 building blocks ───────────────────────────────────────────────────

const OID_RSA = oidBytes(1, 2, 840, 113549, 1, 1, 1);
const OID_SHA256_RSA = oidBytes(1, 2, 840, 113549, 1, 1, 11);
const OID_CN = oidBytes(2, 5, 4, 3);
const OID_KEY_USAGE = oidBytes(2, 5, 29, 15);
const OID_SUBJECT_ALT_NAME = oidBytes(2, 5, 29, 17);
const OID_BASIC_CONSTRAINTS = oidBytes(2, 5, 29, 19);
const OID_EXT_KEY_USAGE = oidBytes(2, 5, 29, 37);
const OID_SERVER_AUTH = oidBytes(1, 3, 6, 1, 5, 5, 7, 3, 1);

/** AlgorithmIdentifier { sha256WithRSAEncryption, NULL } / { rsaEncryption, NULL }. */
const ALG_SHA256_RSA = tlv(0x30, Buffer.concat([tlv(0x06, OID_SHA256_RSA), tlv(0x05, Buffer.alloc(0))]));
const ALG_RSA = tlv(0x30, Buffer.concat([tlv(0x06, OID_RSA), tlv(0x05, Buffer.alloc(0))]));

/** Name (RDNSequence) with a single commonName attribute. */
function nameTlv(commonName) {
  const attribute = tlv(0x30, Buffer.concat([
    tlv(0x06, OID_CN),
    tlv(0x0c, Buffer.from(commonName, "utf8")), // UTF8String
  ]));
  return tlv(0x30, tlv(0x31, attribute)); // SEQUENCE { SET { attribute } }
}

/** Validity: UTCTime before 2050, GeneralizedTime afterwards. */
function timeTlv(date) {
  const year = date.getUTCFullYear();
  const pad2 = (value) => String(value).padStart(2, "0");
  const rest = `${pad2(date.getUTCMonth() + 1)}${pad2(date.getUTCDate())}`
    + `${pad2(date.getUTCHours())}${pad2(date.getUTCMinutes())}${pad2(date.getUTCSeconds())}Z`;
  const text = year < 2050 ? `${pad2(year % 100)}${rest}` : `${year}${rest}`;
  return tlv(year < 2050 ? 0x17 : 0x18, Buffer.from(text, "ascii"));
}

/** 4 or 16 raw bytes for an IPv4/IPv6 literal, or null when invalid. */
function ipBytes(ip) {
  if (ip.includes(".")) {
    const parts = ip.split(".");
    if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
    return Buffer.from(parts.map(Number));
  }
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : halves[0].split(":");
  const tail = halves.length === 2 ? (halves[1] === "" ? [] : halves[1].split(":")) : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const groups = [...head, ...Array(missing).fill("0"), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  const bytes = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) bytes.writeUInt16BE(parseInt(groups[i], 16), i * 2);
  return bytes;
}

/** GeneralName for one SAN entry: "DNS:<name>" or "IP:<v4|v6>". */
function sanGeneralName(san) {
  if (san.startsWith("DNS:")) return tlv(0x82, Buffer.from(san.slice(4), "ascii")); // dNSName [2] IA5String
  if (san.startsWith("IP:")) {
    const bytes = ipBytes(san.slice(3));
    if (bytes === null) throw new Error(`invalid IP SAN: ${san}`);
    return tlv(0x87, bytes); // iPAddress [7] OCTET STRING
  }
  throw new Error(`unsupported SAN type: ${san}`);
}

/**
 * Extension list, sorted by OID per RFC 5280 DER rules:
 * keyUsage (2.5.29.15) < SAN (2.5.29.17) < basicConstraints (2.5.29.19)
 * < extKeyUsage (2.5.29.37).
 */
function buildExtensions(sans) {
  const keyUsage = tlv(0x30, Buffer.concat([
    tlv(0x06, OID_KEY_USAGE),
    tlv(0x01, Buffer.from([0xff])), // critical
    tlv(0x04, tlv(0x03, Buffer.from([0x05, 0xa0]))), // digitalSignature + keyEncipherment
  ]));
  const san = tlv(0x30, Buffer.concat([
    tlv(0x06, OID_SUBJECT_ALT_NAME),
    tlv(0x04, tlv(0x30, Buffer.concat(sans.map(sanGeneralName)))),
  ]));
  const basicConstraints = tlv(0x30, Buffer.concat([
    tlv(0x06, OID_BASIC_CONSTRAINTS),
    tlv(0x01, Buffer.from([0xff])), // critical
    tlv(0x04, tlv(0x30, tlv(0x01, Buffer.from([0xff])))), // SEQUENCE { cA TRUE }
  ]));
  const extKeyUsage = tlv(0x30, Buffer.concat([
    tlv(0x06, OID_EXT_KEY_USAGE),
    tlv(0x04, tlv(0x30, tlv(0x06, OID_SERVER_AUTH))),
  ]));
  return tlv(0xa3, tlv(0x30, Buffer.concat([keyUsage, san, basicConstraints, extKeyUsage])));
}

// ── public API ──────────────────────────────────────────────────────────────

/**
 * Generate a self-signed TLS server certificate.
 * @param options.days - validity in days (default 3650).
 * @param options.commonName - subject/issuer CN (default "DeepSeek Harness Web").
 * @param options.hosts - SAN entries as "DNS:<name>" / "IP:<address>" strings.
 * @returns {{ cert: string, key: string }} PEM certificate and PKCS#8 key.
 */
export function generateSelfSignedCert({ days = 3650, commonName = "DeepSeek Harness Web", hosts = ["DNS:localhost", "IP:127.0.0.1"] } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const sans = [...new Set(hosts)];

  const subject = nameTlv(commonName);
  const spki = tlv(0x30, Buffer.concat([
    ALG_RSA,
    tlv(0x03, Buffer.concat([Buffer.from([0x00]), publicKey.export({ type: "pkcs1", format: "der" })])),
  ]));
  const now = Date.now();
  const tbs = tlv(0x30, Buffer.concat([
    tlv(0xa0, tlv(0x02, Buffer.from([0x02]))), // version [0] EXPLICIT INTEGER v3
    tlv(0x02, integerBytes(randomBytes(16))), // serial
    ALG_SHA256_RSA,
    subject, // issuer == subject (self-signed)
    tlv(0x30, Buffer.concat([timeTlv(new Date(now - 24 * 3600 * 1000)), timeTlv(new Date(now + days * 24 * 3600 * 1000))])),
    subject,
    spki,
    buildExtensions(sans),
  ]));

  const signature = createSign("sha256").update(tbs).sign(privateKey);
  // Self-check before handing the cert out: the signature must verify.
  if (!createVerify("sha256").update(tbs).verify(publicKey, signature)) {
    throw new Error("certificate self-check failed");
  }
  const certDer = tlv(0x30, Buffer.concat([tbs, ALG_SHA256_RSA, tlv(0x03, Buffer.concat([Buffer.from([0x00]), signature]))]));

  return {
    cert: pem("CERTIFICATE", certDer),
    key: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

/** Non-internal IPv4 addresses of this host (certificate SAN material). */
export function lanIpv4s() {
  const out = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) out.push(entry.address);
    }
  }
  return out;
}

/**
 * Load the gateway TLS certificate/key pair, generating a fresh self-signed
 * certificate on first use (random RSA key and serial each run). The
 * generated certificate's SANs cover localhost, the loopback address and
 * every non-internal IPv4 address of this host, so remote https access via a
 * LAN IP presents a matching certificate. Existing files are never
 * overwritten — hand them to {@link generateSelfSignedCert} docs or the
 * `dsh-web-auth gen-cert` CLI for regeneration.
 * @param certFile - PEM certificate path.
 * @param keyFile - PEM private-key path.
 * @param options.days - validity in days for a generated certificate.
 * @returns {{cert: Buffer|string, key: Buffer|string, created: boolean}}
 *   `created` reports whether the pair was freshly generated.
 */
export function loadOrCreateTls(certFile, keyFile, { days = 3650 } = {}) {
  try {
    return { cert: readFileSync(certFile), key: readFileSync(keyFile), created: false };
  } catch {
    /* first use — generate below */
  }
  const hosts = ["DNS:localhost", "IP:127.0.0.1", ...lanIpv4s().map((ip) => `IP:${ip}`)];
  const { cert, key } = generateSelfSignedCert({ days, hosts });
  mkdirSync(dirname(certFile), { recursive: true });
  writeFileSync(certFile, cert, { mode: 0o644 });
  writeFileSync(keyFile, key, { mode: 0o600 });
  return { cert, key, created: true };
}
