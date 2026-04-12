/**
 * Guard SOC - Client Integration Middleware
 * -----------------------------------------
 * This script connects your website/app to the Guard AI engine.
 * 
 * Instructions:
 * 1. Add your Guard API Key to your .env file as GUARD_SOC_KEY.
 * 2. Import this module into your Express/Next.js/Node provider.
 * 3. Use the 'protect' middleware to monitor all incoming requests.
 */

const fetch = require('node-fetch'); // Standard for older Node versions

const GUARD_CONFIG = {
    endpoint: "https://guard-soc.onrender.com/api/run",
    apiKey: process.env.GUARD_KEY || "your-key-here"
};

/**
 * Main Middleware Function
 */
async function guardProtect(req, res, next) {
    try {
        // Prepare the payload for the AI SOC
        const threatPayload = {
            threat_type: _detectContext(req),
            payload: {
                path: req.path,
                method: req.method,
                query: req.query,
                body: req.body,
                ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
            }
        };

        // Send to Guard for Analysis (Non-blocking for real-time feel)
        // We do NOT 'await' here because we don't want to slow down your legitimate users
        _fireAndForget(threatPayload);

        next();
    } catch (err) {
        console.error("Guard SOC Communication Error:", err);
        next(); // Always fail open to avoid crashing your site
    }
}

/**
 * Internal: Determines which agent should monitor the request
 */
function _detectContext(req) {
    if (Object.keys(req.query || {}).length > 0) return "db"; // Monitor URL params for SQLi
    if (req.method === "POST") return "db"; // Monitor bodies for SQLi
    return "log"; // Default to general log monitoring
}

/**
 * Internal: Sends data asychronously to avoid latency
 */
function _fireAndForget(payload) {
    fetch(GUARD_CONFIG.endpoint, {
        method: 'POST',
        headers: {
            'X-API-Key': GUARD_CONFIG.apiKey,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    }).catch(err => {
        // Silent fail - don't spam client logs unless it's a critical auth error
    });
}

module.exports = { guardProtect };
