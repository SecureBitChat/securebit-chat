// Local QR generator and scanner with COSE compression (no external CDNs)
// Exposes: 
// - window.generateQRCode(text, { size?: number, margin?: number, errorCorrectionLevel?: 'L'|'M'|'Q'|'H' })
// - window.generateCOSEQRCode(data, senderKey?, recipientKey?) - COSE-based compression
// - window.Html5Qrcode (for scanning QR codes)
// - window.packSecurePayload, window.receiveAndProcess (COSE functions)

import * as QRCode from 'qrcode';
import { Html5Qrcode } from 'html5-qrcode';
import { gzip, ungzip, deflate, inflate } from 'pako';
import * as cbor from 'cbor-js';
import { packSecurePayload, receiveAndProcess } from '../crypto/cose-qr.js';
import {
  decodeDescriptor as sbq2Decode,
  decodeText as sbq2DecodeText,
  encodeText as sbq2EncodeText,
  TYPE as SBQ2_TYPE,
  TEXT_PREFIX as SBQ2_TEXT_PREFIX,
} from '../network/descriptor/sbq2.js';

// Compact payload prefix to signal gzip+base64 content
const COMPRESSION_PREFIX = 'SB1:gz:';
const BINARY_PREFIX = 'SB1:bin:'; // CBOR + deflate + base64url

function uint8ToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function compressStringToBase64Gzip(text) {
  const utf8 = new TextEncoder().encode(text);
  const gz = gzip(utf8);
  return uint8ToBase64(gz);
}

function decompressBase64GzipToString(b64) {
  const gz = base64ToUint8(b64);
  const out = ungzip(gz);
  return new TextDecoder().decode(out);
}

async function generateQRCode(text, opts = {}) {
  const size = opts.size || 512;
  const margin = opts.margin ?? 2;
  const errorCorrectionLevel = opts.errorCorrectionLevel || 'M';
  return await QRCode.toDataURL(text, { width: size, margin, errorCorrectionLevel });
}

// Generate QR with gzip+base64 payload and recognizable prefix for scanners
async function generateCompressedQRCode(text, opts = {}) {
  try {
    const compressedB64 = compressStringToBase64Gzip(text);
    const payload = COMPRESSION_PREFIX + compressedB64;
    return await generateQRCode(payload, opts);
  } catch (e) {
    console.warn('generateCompressedQRCode failed, falling back to plain:', e?.message || e);
    return await generateQRCode(text, opts);
  }
}

// ---- Binary (CBOR) encode/decode helpers ----
function base64ToBase64Url(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function base64UrlToBase64(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad) b64 += '='.repeat(4 - pad);
  return b64;
}

function encodeObjectToBinaryBase64Url(obj) {
  const cborBytes = cbor.encode(obj);
  const compressed = deflate(new Uint8Array(cborBytes));
  const b64 = uint8ToBase64(compressed);
  return base64ToBase64Url(b64);
}

function decodeBinaryBase64UrlToObject(b64url) {
  const b64 = base64UrlToBase64(b64url);
  const compressed = base64ToUint8(b64);
  const decompressed = inflate(compressed);
  const ab = decompressed.buffer.slice(decompressed.byteOffset, decompressed.byteOffset + decompressed.byteLength);
  return cbor.decode(ab);
}

async function generateBinaryQRCodeFromObject(obj, opts = {}) {
  try {
    const b64url = encodeObjectToBinaryBase64Url(obj);
    const payload = BINARY_PREFIX + b64url;
    return await generateQRCode(payload, opts);
  } catch (e) {
    console.warn('generateBinaryQRCodeFromObject failed, falling back to JSON compressed:', e?.message || e);
    const text = JSON.stringify(obj);
    return await generateCompressedQRCode(text, opts);
  }
}

// COSE-based QR generation for large data
async function generateCOSEQRCode(data, senderKey = null, recipientKey = null) {
    try {
        console.log('🔐 Generating COSE-based QR code...');
        
        // Pack data using COSE
        const chunks = await packSecurePayload(data, senderKey, recipientKey);
        
        if (chunks.length === 1) {
            // Single QR code
            return await generateQRCode(chunks[0]);
        } else {
            // Enforce single-QR policy: let caller fallback to template/reference
            console.warn(`📊 COSE packing produced ${chunks.length} chunks; falling back to non-COSE strategy`);
            throw new Error('COSE QR would require multiple chunks');
        }
    } catch (error) {
        console.error('Error generating COSE QR code:', error);
        throw error;
    }
}

// Expose functions to global scope
window.generateQRCode = generateQRCode;
window.generateCompressedQRCode = generateCompressedQRCode;
window.generateBinaryQRCodeFromObject = generateBinaryQRCodeFromObject;
window.generateCOSEQRCode = generateCOSEQRCode;
window.Html5Qrcode = Html5Qrcode;
window.packSecurePayload = packSecurePayload;
window.receiveAndProcess = receiveAndProcess;

// Expose helper to transparently decompress scanner payloads
window.decompressIfNeeded = function (scannedText) {
  try {
    if (typeof scannedText === 'string' && scannedText.startsWith(COMPRESSION_PREFIX)) {
      const b64 = scannedText.slice(COMPRESSION_PREFIX.length);
      return decompressBase64GzipToString(b64);
    }
  } catch (e) {
    console.warn('decompressIfNeeded failed:', e?.message || e);
  }
  return scannedText;
};

// Expose helper to get compressed string with prefix for copy/paste flows
window.compressToPrefixedGzip = function (text) {
  try {
    const payload = String(text || '');
    const compressedB64 = compressStringToBase64Gzip(payload);
    return COMPRESSION_PREFIX + compressedB64;
  } catch (e) {
    console.warn('compressToPrefixedGzip failed:', e?.message || e);
    return String(text || '');
  }
};

// Expose helpers for binary payloads in copy/paste
window.encodeBinaryToPrefixed = function (objOrJson) {
  try {
    const obj = typeof objOrJson === 'string' ? JSON.parse(objOrJson) : objOrJson;
    // An SBQ2 descriptor is already its own compact wire form. Re-encoding it as
    // CBOR+deflate+base64 would wrap 124 bytes back up into ~200 characters of
    // SB1 envelope and undo the entire point.
    if (obj && typeof obj.sbq2 === 'string') return obj.sbq2;
    const b64url = encodeObjectToBinaryBase64Url(obj);
    return BINARY_PREFIX + b64url;
  } catch (e) {
    console.warn('encodeBinaryToPrefixed failed:', e?.message || e);
    return typeof objOrJson === 'string' ? objOrJson : JSON.stringify(objOrJson);
  }
};

window.decodeAnyPayload = function (scannedText) {
  try {
    if (typeof scannedText === 'string') {
      // SBQ2 first. The two families are distinguishable without guessing: an
      // SBQ2 payload is `SB2:` + base64url, an SB1 one is `SB1:bin:`/`SB1:gz:`,
      // and a raw-byte SBQ2 descriptor starts with 0x02 where any SB1 text
      // starts with ASCII 'S' (0x53).
      if (scannedText.startsWith(SBQ2_TEXT_PREFIX)) {
        const bytes = sbq2DecodeText(scannedText);
        const desc = sbq2Decode(bytes);
        // Hand back the shape the app already routes on, with the compact form
        // attached for the manager to re-parse. The manager decodes it again
        // from the text rather than trusting anything decided here — this layer
        // only classifies.
        return { t: desc.type === SBQ2_TYPE.OFFER ? 'offer' : 'answer', sbq2: scannedText };
      }
      if (scannedText.charCodeAt(0) === 0x02) {
        const bytes = Uint8Array.from(scannedText, (c) => c.charCodeAt(0) & 0xff);
        const desc = sbq2Decode(bytes);
        return { t: desc.type === SBQ2_TYPE.OFFER ? 'offer' : 'answer', sbq2: sbq2EncodeText(bytes) };
      }
      // A payload from a FUTURE format generation. Recognising the family
      // without being able to read it is the one case where we can say
      // something useful instead of letting JSON.parse produce
      // "Unexpected token 'S'". Every descriptor family is `SB<n>:`, so this
      // stays true for SB3 and beyond without another release.
      const family = /^SB(\d+):/.exec(scannedText);
      if (family && family[1] !== '1' && family[1] !== '2') {
        throw new Error(
          'This invitation was created by a newer version of SecureBit. ' +
          'Please update the app to connect.'
        );
      }

      if (scannedText.startsWith(BINARY_PREFIX)) {
        const b64url = scannedText.slice(BINARY_PREFIX.length);
        return decodeBinaryBase64UrlToObject(b64url); // returns object
      }
      if (scannedText.startsWith(COMPRESSION_PREFIX)) {
        const s = window.decompressIfNeeded(scannedText);
        return s; // returns JSON string
      }
      // Not prefixed: return as-is
      return scannedText;
    }
  } catch (e) {
    // A payload that announced itself as SBQ2 and then failed to decode must not
    // fall through to the SB1 parser, which would report a generic "invalid
    // format" for what is really a strict-decoder rejection (bad version,
    // unknown extension, trailing bytes, expired). Surface it.
    if (typeof scannedText === 'string' &&
        (scannedText.startsWith(SBQ2_TEXT_PREFIX) ||
         scannedText.charCodeAt(0) === 0x02 ||
         /^SB(\d+):/.test(scannedText))) {
      throw e;
    }
    console.warn('decodeAnyPayload failed:', e?.message || e);
  }
  return scannedText;
};

console.log('QR libraries loaded: generateQRCode, generateCompressedQRCode, generateBinaryQRCodeFromObject, Html5Qrcode, COSE functions');