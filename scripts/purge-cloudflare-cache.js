/**
 * Скрипт для очистки кеша Cloudflare после деплоя
 * 
 * Использование:
 * CLOUDFLARE_API_TOKEN=your_token CLOUDFLARE_ZONE_ID=your_zone_id node scripts/purge-cloudflare-cache.js
 */

const https = require('https');

const API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const ZONE_ID = process.env.CLOUDFLARE_ZONE_ID;
const DOMAIN = process.env.CLOUDFLARE_DOMAIN || 'securebit.chat';

if (!API_TOKEN || !ZONE_ID) {
    console.error('❌ Missing required environment variables:');
    console.error('   CLOUDFLARE_API_TOKEN - Cloudflare API Token');
    console.error('   CLOUDFLARE_ZONE_ID - Cloudflare Zone ID');
    process.exit(1);
}

// Критичные файлы для очистки
const CRITICAL_FILES = [
    `https://${DOMAIN}/meta.json`,
    `https://${DOMAIN}/index.html`,
    `https://${DOMAIN}/sw.js`,
    `https://${DOMAIN}/manifest.json`
];

async function purgeCache(files) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify({
            files: files
        });

        const options = {
            hostname: 'api.cloudflare.com',
            port: 443,
            path: `/client/v4/zones/${ZONE_ID}/purge_cache`,
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${API_TOKEN}`,
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        };

        const req = https.request(options, (res) => {
            let responseData = '';

            res.on('data', (chunk) => {
                responseData += chunk;
            });

            res.on('end', () => {
                if (res.statusCode === 200) {
                    const result = JSON.parse(responseData);
                    if (result.success) {
                        resolve(result);
                    } else {
                        reject(new Error(JSON.stringify(result.errors)));
                    }
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${responseData}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.write(data);
        req.end();
    });
}

async function main() {
    console.log('🔄 Purging Cloudflare cache...');
    console.log(`   Zone ID: ${ZONE_ID}`);
    console.log(`   Domain: ${DOMAIN}`);
    console.log(`   Files: ${CRITICAL_FILES.length}`);

    try {
        const result = await purgeCache(CRITICAL_FILES);
        console.log('✅ Cache purged successfully');
        console.log(`   Purged files: ${result.result.files?.length || 0}`);
    } catch (error) {
        console.error('❌ Failed to purge cache:', error.message);
        process.exit(1);
    }
}

main();

