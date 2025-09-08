// Local QR generator adapter (no external CDNs)
// Exposes: window.generateQRCode(text, { size?: number, margin?: number, errorCorrectionLevel?: 'L'|'M'|'Q'|'H' })

import * as QRCode from 'qrcode';

async function generateQRCode(text, opts = {}) {
  const size = opts.size || 300;
  const margin = opts.margin ?? 2;
  const errorCorrectionLevel = opts.errorCorrectionLevel || 'M';
  return await QRCode.toDataURL(text, { width: size, margin, errorCorrectionLevel });
}

window.generateQRCode = generateQRCode;
