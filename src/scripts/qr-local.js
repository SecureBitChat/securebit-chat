// Local QR generator and scanner with COSE compression (no external CDNs)
// Exposes: 
// - window.generateQRCode(text, { size?: number, margin?: number, errorCorrectionLevel?: 'L'|'M'|'Q'|'H' })
// - window.generateCOSEQRCode(data, senderKey?, recipientKey?) - COSE-based compression
// - window.Html5Qrcode (for scanning QR codes)
// - window.packSecurePayload, window.receiveAndProcess (COSE functions)

import * as QRCode from 'qrcode';
import { Html5Qrcode } from 'html5-qrcode';
import { packSecurePayload, receiveAndProcess } from '../crypto/cose-qr.js';

async function generateQRCode(text, opts = {}) {
  const size = opts.size || 512;
  const margin = opts.margin ?? 2;
  const errorCorrectionLevel = opts.errorCorrectionLevel || 'M';
  return await QRCode.toDataURL(text, { width: size, margin, errorCorrectionLevel });
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
window.generateCOSEQRCode = generateCOSEQRCode;
window.Html5Qrcode = Html5Qrcode;
window.packSecurePayload = packSecurePayload;
window.receiveAndProcess = receiveAndProcess;

console.log('QR libraries loaded: generateQRCode, generateCOSEQRCode, Html5Qrcode, COSE functions');