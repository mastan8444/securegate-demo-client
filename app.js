const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

// Your Live AWS SecureGate AI Gateway
const GATEWAY = "http://3.238.2.113";

// API key for the System tenant
const API_KEY = "sg_live_default_system_secret_key_123456";

// Security Filter Middleware
app.use(async (req, res, next) => {
    // Skip static assets or favicon requests
    if (req.path === "/favicon.ico") {
        return next();
    }

    // 1. Resolve client IP:
    // When deployed on the cloud, req.headers['x-forwarded-for'] or req.socket.remoteAddress
    // will automatically contain the visitor's real public IP address.
    let visitorIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // If the visitor is visiting from localhost (local testing), fallback to standard test IP
    // or allow overriding via query parameter e.g., ?ip=10.10.10.10
    if (visitorIp === "::1" || visitorIp === "127.0.0.1" || visitorIp === "::ffff:127.0.0.1") {
        visitorIp = req.query.ip || "192.168.1.99";
    }

    try {
        // Query your live AWS checking gateway
        const response = await axios.get(
            `${GATEWAY}/api/check/${visitorIp}?apiKey=${API_KEY}`
        );

        console.log(`[SecureGate AI] Check IP: ${visitorIp} -> Allowed: ${response.data.allowed}`);

        if (response.data.allowed) {
            req.visitorIp = visitorIp; // Pass IP to next handlers
            next();
        } else {
            return res.status(403).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Access Blocked - SecureGate AI</title>
                    <style>
                        body { background-color: #080c14; color: #fff; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                        .card { background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 20px; padding: 40px; text-align: center; max-width: 450px; }
                        h1 { color: #ef4444; font-size: 2.2rem; margin-top: 0; }
                        p { color: #94a3b8; line-height: 1.6; }
                        .ip { font-family: monospace; background: rgba(255,255,255,0.05); padding: 5px 10px; border-radius: 5px; color: #fff; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <h1>⚠️ Access Blocked</h1>
                        <p>Your request from IP <span class="ip">${visitorIp}</span> was rejected by the <strong>SecureGate AI</strong> protection rules configured for this website.</p>
                        <p>Reason: ${response.data.reason || "IP Blacklisted"}</p>
                    </div>
                </body>
                </html>
            `);
        }

    } catch (err) {
        // Fail-Safe: If your security gateway is temporarily unreachable, let requests pass
        console.log(`[SecureGate AI] Gateway Connection Error: ${err.message}. Failing safe.`);
        next();
    }
});

app.get("/", (req, res) => {
    const visitorIp = req.visitorIp || "192.168.1.99";

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureGate AI Client Demo</title>
            <style>
                body {
                    background-color: #080c14;
                    color: #fff;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                }
                .card {
                    background: rgba(15, 23, 42, 0.65);
                    border: 1px solid rgba(255, 255, 255, 0.05);
                    border-radius: 24px;
                    padding: 40px;
                    max-width: 500px;
                    width: 100%;
                    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
                    text-align: center;
                }
                h1 { margin-bottom: 5px; font-weight: 800; font-size: 2rem; }
                h2 { color: #06b6d4; margin-top: 0; font-weight: 500; font-size: 1.1rem; }
                .status-badge {
                    display: inline-block;
                    background-color: rgba(16, 185, 129, 0.08);
                    border: 1px solid rgba(16, 185, 129, 0.2);
                    color: #10b981;
                    padding: 8px 20px;
                    border-radius: 20px;
                    font-weight: 700;
                    font-size: 0.85rem;
                    margin: 20px 0;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                .ip-box {
                    background: rgba(255, 255, 255, 0.02);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 12px;
                    padding: 15px;
                    font-family: monospace;
                    font-size: 1.3rem;
                    margin: 15px 0;
                    color: #38bdf8;
                }
                .btn {
                    display: block;
                    width: 100%;
                    background: #6366f1;
                    color: white;
                    border: none;
                    padding: 14px;
                    border-radius: 12px;
                    font-weight: 700;
                    cursor: pointer;
                    margin-top: 15px;
                    transition: all 0.2s;
                    font-size: 0.95rem;
                }
                .btn:hover { background: #4f46e5; }
                .btn-danger { background: #ef4444; }
                .btn-danger:hover { background: #dc2626; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Customer Website</h1>
                <h2>Protected by SecureGate AI</h2>
                <div class="status-badge">🛡️ Protected & Allowed</div>
                <p>Your current client IP is evaluated as:</p>
                <div class="ip-box">${visitorIp}</div>
                <p style="color: #64748b; font-size: 0.85rem;">To simulate other client IPs, append query parameter: <code>?ip=10.10.10.10</code></p>
                <hr style="border: 0; height: 1px; background: rgba(255,255,255,0.06); margin: 25px 0;">
                <h3 style="margin-bottom: 10px;">Threat Simulation Lab</h3>
                <button class="btn btn-danger" onclick="triggerBruteForce()">Simulate Brute Force Attack (5 Failed Logins)</button>
                <script>
                    async function triggerBruteForce() {
                        if (confirm('This will register 5 failed login attempts for IP ${visitorIp} on your live AWS gateway, triggering an automatic block. Proceed?')) {
                            // Send 5 failed login simulation requests directly to your AWS gateway
                            for (let i = 0; i < 5; i++) {
                                await fetch('${GATEWAY}/api/simulate/failed-login', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ ip: '${visitorIp}', apiKey: '${API_KEY}' })
                                });
                            }
                            alert('Brute force attack simulated! Press OK to reload and verify blocking.');
                            window.location.reload();
                        }
                    }
                </script>
            </div>
        </body>
        </html>
    `);
});

app.listen(3000, () => {
    console.log("Customer website running on port 3000");
});
