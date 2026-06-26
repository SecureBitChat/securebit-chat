/**
 * post-build.js - Script for generating meta.json after build
 * 
 * Generates meta.json file with unique build version (timestamp)
 * for automatic update detection
 */

const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    // Path to public directory (project root where index.html is located)
    publicDir: path.join(__dirname, '..'),
    
    // meta.json filename
    metaFileName: 'meta.json',
    
    // Version format: 'timestamp' or 'semver'
    versionFormat: 'timestamp'
};

/**
 * Generate unique build version
 */
function generateBuildVersion() {
    // Use timestamp for uniqueness of each build
    const timestamp = Date.now();
    
    // Optional: can add git commit hash
    let gitHash = '';
    try {
        const { execSync } = require('child_process');
        gitHash = execSync('git rev-parse --short HEAD', { encoding: 'utf-8' }).trim();
    } catch (error) {
        // Git not available or not initialized - ignore
    }
    
    return {
        version: timestamp.toString(),
        buildTime: new Date().toISOString(),
        gitHash: gitHash || null,
        buildId: `${timestamp}${gitHash ? `-${gitHash}` : ''}`
    };
}

/**
 * Read package.json to get application version
 */
function getAppVersion() {
    try {
        const packageJsonPath = path.join(__dirname, '..', 'package.json');
        if (fs.existsSync(packageJsonPath)) {
            const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
            return packageJson.version || '1.0.0';
        }
    } catch (error) {
        console.warn('⚠️  Failed to read package.json:', error.message);
    }
    return '1.0.0';
}

/**
 * Generate meta.json
 */
function generateMetaJson() {
    try {
        const buildInfo = generateBuildVersion();
        const appVersion = getAppVersion();
        
        const meta = {
            // Build version (used for update checking)
            version: buildInfo.version,
            buildVersion: buildInfo.version,
            
            // Application version from package.json
            appVersion: appVersion,
            
            // Additional information
            buildTime: buildInfo.buildTime,
            buildId: buildInfo.buildId,
            gitHash: buildInfo.gitHash,
            
            // Metadata
            generated: true,
            generatedAt: new Date().toISOString()
        };
        
        // Path to meta.json file (in project root where index.html is located)
        const metaFilePath = path.join(CONFIG.publicDir, CONFIG.metaFileName);
        
        // Create directory if it doesn't exist
        const publicDir = path.dirname(metaFilePath);
        if (!fs.existsSync(publicDir)) {
            fs.mkdirSync(publicDir, { recursive: true });
            console.log(`✅ Created directory: ${publicDir}`);
        }
        
        // Write meta.json
        fs.writeFileSync(
            metaFilePath,
            JSON.stringify(meta, null, 2),
            'utf-8'
        );
        
        console.log('✅ meta.json generated successfully');
        console.log(`   Version: ${meta.version}`);
        console.log(`   Build Time: ${meta.buildTime}`);
        if (meta.gitHash) {
            console.log(`   Git Hash: ${meta.gitHash}`);
        }
        console.log(`   File: ${metaFilePath}`);
        
        return meta;
        
    } catch (error) {
        console.error('❌ Failed to generate meta.json:', error);
        process.exit(1);
    }
}

/**
 * Update versions in index.html
 */
function updateIndexHtmlVersions(buildVersion) {
    try {
        const indexHtmlPath = path.join(CONFIG.publicDir, 'index.html');
        
        if (!fs.existsSync(indexHtmlPath)) {
            console.warn('⚠️  index.html not found, skipping version update');
            return;
        }
        
        let indexHtml = fs.readFileSync(indexHtmlPath, 'utf-8');
        
        // Update versions in query parameters for JS files
        // Pattern: src="dist/app.js?v=..." or src="dist/app-boot.js?v=..."
        // Also replace BUILD_VERSION placeholder
        indexHtml = indexHtml.replace(/\?v=BUILD_VERSION/g, `?v=${buildVersion}`);
        indexHtml = indexHtml.replace(/\?v=(\d+)/g, `?v=${buildVersion}`);
        
        fs.writeFileSync(indexHtmlPath, indexHtml, 'utf-8');
        console.log('✅ index.html versions updated');

    } catch (error) {
        console.warn('⚠️  Failed to update index.html versions:', error.message);
    }
}

/**
 * Stamp the build version into sw.js so the file's bytes change every deploy. The browser
 * only reinstalls a Service Worker when sw.js differs byte-for-byte; without this the SW
 * (and its caches) stay frozen and clients never pick up new releases automatically.
 */
function updateServiceWorkerVersion(buildVersion) {
    try {
        const swPath = path.join(CONFIG.publicDir, 'sw.js');
        if (!fs.existsSync(swPath)) {
            console.warn('⚠️  sw.js not found, skipping SW version stamp');
            return;
        }
        let sw = fs.readFileSync(swPath, 'utf-8');
        if (/const SW_BUILD_VERSION = '[^']*';/.test(sw)) {
            sw = sw.replace(/const SW_BUILD_VERSION = '[^']*';/, `const SW_BUILD_VERSION = '${buildVersion}';`);
            fs.writeFileSync(swPath, sw, 'utf-8');
            console.log(`✅ sw.js build stamp updated → ${buildVersion}`);
        } else {
            console.warn('⚠️  SW_BUILD_VERSION marker not found in sw.js');
        }
    } catch (error) {
        console.warn('⚠️  Failed to stamp sw.js version:', error.message);
    }
}

/**
 * Validate generated meta.json
 */
function validateMetaJson(meta) {
    const requiredFields = ['version', 'buildVersion', 'buildTime'];
    const missingFields = requiredFields.filter(field => !meta[field]);
    
    if (missingFields.length > 0) {
        throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
    }
    
    if (!/^\d+$/.test(meta.version)) {
        throw new Error(`Invalid version format: ${meta.version} (expected timestamp)`);
    }
    
    console.log('✅ meta.json validation passed');
}

// Main function
function main() {
    console.log('🔨 Generating meta.json...');
    console.log(`   Public directory: ${CONFIG.publicDir}`);
    
    // Check if public directory exists
    if (!fs.existsSync(CONFIG.publicDir)) {
        console.error(`❌ Public directory not found: ${CONFIG.publicDir}`);
        process.exit(1);
    }
    
    // Generate meta.json
    const meta = generateMetaJson();
    
    // Validate
    validateMetaJson(meta);
    
    // Update versions in index.html
    updateIndexHtmlVersions(meta.version);

    // Stamp the build version into sw.js so the Service Worker reinstalls each deploy.
    updateServiceWorkerVersion(meta.version);

    console.log('✅ Build metadata generation completed');
}

// Run script
if (require.main === module) {
    main();
}

// Export for use in other scripts
module.exports = {
    generateMetaJson,
    generateBuildVersion,
    getAppVersion,
    validateMetaJson
};

