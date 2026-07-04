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

    // Resolve client IP
    let visitorIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Normalize localhost ipv6/ipv4 loopback
    if (visitorIp === "::1" || visitorIp === "127.0.0.1" || visitorIp === "::ffff:127.0.0.1") {
        visitorIp = req.query.ip || "192.168.1.99";
    }

    // Pass resolved IP to handlers
    req.visitorIp = visitorIp;

    // Skip check for the login post request itself so the app can register the attempt
    if (req.path === "/login" && req.method === "POST") {
        return next();
    }

    try {
        // Query your live AWS checking gateway
        const response = await axios.get(
            `${GATEWAY}/api/check/${visitorIp}?apiKey=${API_KEY}`
        );

        if (response.data.allowed) {
            next();
        } else {
            return res.status(403).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Access Blocked - SecureGate AI</title>
                    <style>
                        body { background-color: #080c14; color: #fff; font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                        .card { background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 20px; padding: 40px; text-align: center; max-width: 450px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
                        h1 { color: #ef4444; font-size: 2.2rem; margin-top: 0; }
                        p { color: #94a3b8; line-height: 1.6; }
                        .ip { font-family: monospace; background: rgba(255,255,255,0.05); padding: 5px 10px; border-radius: 5px; color: #fff; }
                        .footer { margin-top: 25px; font-size: 0.85rem; color: #64748b; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <h1>⚠️ Access Blocked</h1>
                        <p>Your request from IP <span class="ip">${visitorIp}</span> was rejected by the <strong>SecureGate AI</strong> protection rules configured for this website.</p>
                        <p>Reason: ${response.data.reason || "IP Blacklisted due to brute force login attempts"}</p>
                        <div class="footer">SecureGate AI Protection Shield v1.0</div>
                    </div>
                </body>
                </html>
            `);
        }

    } catch (err) {
        // Safe-Fail: If the firewall gateway is offline, let requests pass so customer's site stays online
        console.log(`[SecureGate AI] Gateway Connection Error: ${err.message}. Failing safe.`);
        next();
    }
});

// Root Route: Renders the Bank Login Form
app.get("/", (req, res) => {
    const visitorIp = req.visitorIp;

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Login - Customer Portal</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
                    max-width: 400px;
                    width: 100%;
                    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                h1 { margin: 0; font-weight: 800; font-size: 1.8rem; letter-spacing: -0.5px; }
                h2 { color: #6366f1; margin: 5px 0 0 0; font-weight: 600; font-size: 0.95rem; text-transform: uppercase; letter-spacing: 1px; }
                .input-group {
                    margin-bottom: 20px;
                    text-align: left;
                }
                label {
                    display: block;
                    margin-bottom: 8px;
                    color: #94a3b8;
                    font-size: 0.9rem;
                    font-weight: 500;
                }
                input {
                    width: 100%;
                    box-sizing: border-box;
                    background: rgba(255, 255, 255, 0.02);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 12px;
                    padding: 14px;
                    color: #fff;
                    font-size: 1rem;
                    transition: all 0.2s;
                }
                input:focus {
                    outline: none;
                    border-color: #6366f1;
                    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
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
                    margin-top: 25px;
                    transition: all 0.2s;
                    font-size: 1rem;
                }
                .btn:hover { background: #4f46e5; }
                .error-box {
                    display: none;
                    background-color: rgba(239, 68, 68, 0.06);
                    border: 1px solid rgba(239, 68, 68, 0.2);
                    color: #f87171;
                    padding: 12px;
                    border-radius: 12px;
                    margin-bottom: 20px;
                    font-size: 0.88rem;
                    line-height: 1.4;
                    text-align: center;
                }
                .ip-footer {
                    text-align: center;
                    margin-top: 30px;
                    font-size: 0.8rem;
                    color: #475569;
                }
                .ip-val {
                    color: #38bdf8;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="header">
                    <h2>ABC Secure Bank</h2>
                    <h1>Sign In to Portal</h1>
                </div>

                <div class="error-box" id="errorBox"></div>

                <form id="loginForm" onsubmit="handleLogin(event)">
                    <div class="input-group">
                        <label>Username</label>
                        <input type="text" id="username" placeholder="Enter username" required>
                    </div>
                    <div class="input-group">
                        <label>Password</label>
                        <input type="password" id="password" placeholder="Enter password" required>
                    </div>
                    <button type="submit" class="btn" id="loginBtn">Secure Log In</button>
                </form>

                <div class="ip-footer">
                    Connecting from IP: <span class="ip-val">${visitorIp}</span>
                </div>
            </div>

            <script>
                async function handleLogin(e) {
                    e.preventDefault();
                    const u = document.getElementById('username').value;
                    const p = document.getElementById('password').value;
                    const errorBox = document.getElementById('errorBox');
                    const loginBtn = document.getElementById('loginBtn');

                    errorBox.style.display = 'none';
                    loginBtn.disabled = true;
                    loginBtn.innerText = 'Authenticating...';

                    try {
                        const response = await fetch('/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username: u, password: p })
                        });

                        const result = await response.json();

                        if (result.status === 'BLOCKED') {
                            // If blocked, reload the page to trigger the middleware lock screen
                            window.location.reload();
                        } else {
                            // Show error message (invalid password)
                            errorBox.innerText = result.message;
                            errorBox.style.display = 'block';
                            document.getElementById('password').value = '';
                        }
                    } catch (err) {
                        errorBox.innerText = 'Server connection failed.';
                        errorBox.style.display = 'block';
                    } finally {
                        loginBtn.disabled = false;
                        loginBtn.innerText = 'Secure Log In';
                    }
                }
            </script>
        </body>
        </html>
    `);
});

// POST /login: Process login attempt and report failure to gateway
app.post("/login", async (req, res) => {
    const visitorIp = req.visitorIp;

    try {
        // 1. Report failed attempt to the live AWS gateway
        await axios.post(`${GATEWAY}/api/simulate/failed-login`, {
            ip: visitorIp,
            apiKey: API_KEY
        });

        // 2. Check if the IP is now blocked
        const checkResponse = await axios.get(
            `${GATEWAY}/api/check/${visitorIp}?apiKey=${API_KEY}`
        );

        if (!checkResponse.data.allowed) {
            return res.json({
                status: "BLOCKED",
                message: "Access blocked: Too many failed attempts."
            });
        } else {
            return res.json({
                status: "FAILED",
                message: "Invalid username or password. Multiple failed attempts will trigger an automatic security ban."
            });
        }

    } catch (err) {
        console.log(`[SecureGate AI] Login check failed: ${err.message}`);
        return res.json({
            status: "FAILED",
            message: "Invalid username or password."
        });
    }
});

app.listen(3000, () => {
    console.log("Customer website running on port 3000");
});
