/**
 * Splunk MCP Connector
 * Bridges Splunk REST API to the SOC agent via HTTP endpoints.
 */

require('dotenv').config({ path: '../.env' });
const express = require('express');
const axios = require('axios');
const https = require('https');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const config = {
    splunkHost: process.env.SPLUNK_HOST || 'localhost',
    splunkPort: process.env.SPLUNK_PORT || 8089,
    splunkUsername: process.env.SPLUNK_USERNAME || 'admin',
    splunkPassword: process.env.SPLUNK_PASSWORD || '',
    splunkToken: process.env.SPLUNK_TOKEN || '',
    splunkMcpEndpoint: process.env.SPLUNK_MCP_ENDPOINT || 'https://localhost:8089/services/mcp',
    nodePort: process.env.NODE_PORT || 3000,
    verifySsl: process.env.SPLUNK_VERIFY_SSL === 'true',
    debug: process.env.DEBUG === 'true'
};

function log(message, data = null) {
    if (config.debug) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] ${message}`);
        if (data) console.log(JSON.stringify(data, null, 2));
    }
}

const httpsAgent = new https.Agent({ rejectUnauthorized: config.verifySsl });
const splunkBaseUrl = `https://${config.splunkHost}:${config.splunkPort}`;

function getAuthHeaders() {
    const auth = Buffer.from(`${config.splunkUsername}:${config.splunkPassword}`).toString('base64');
    return { 'Authorization': `Basic ${auth}` };
}

app.get('/health', (req, res) => {
    log('Health check requested');
    res.json({ status: 'ok', service: 'splunk-mcp-connector' });
});

app.get('/api/splunk/test', async (req, res) => {
    log('Testing Splunk connectivity...');
    try {
        const response = await axios.get(`${splunkBaseUrl}/services/server/info`, {
            headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
            httpsAgent,
            params: { output_mode: 'json' }
        });
        log('Splunk connection successful', response.data);
        res.json({
            status: 'connected',
            splunkVersion: response.data.entry?.[0]?.content?.version || 'unknown',
            serverName: response.data.entry?.[0]?.content?.serverName || 'unknown'
        });
    } catch (error) {
        log('Splunk connection failed', { error: error.message, code: error.code });
        res.status(500).json({
            status: 'error',
            message: error.message,
            hint: 'Check port 8089, credentials, and SSL settings'
        });
    }
});

app.post('/api/splunk/search', async (req, res) => {
    const { query, earliest_time = '-24h', latest_time = 'now' } = req.body;
    log('Executing Splunk search', { query, earliest_time, latest_time });

    if (!query) {
        return res.status(400).json({ error: 'Query is required' });
    }

    try {
        const createJobResponse = await axios.post(
            `${splunkBaseUrl}/services/search/jobs`,
            new URLSearchParams({
                search: `search ${query}`,
                earliest_time,
                latest_time,
                output_mode: 'json'
            }),
            {
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/x-www-form-urlencoded' },
                httpsAgent
            }
        );

        const sid = createJobResponse.data.sid;
        log('Search job created', { sid });

        let isDone = false;
        let attempts = 0;
        const maxAttempts = 60;

        while (!isDone && attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 1000));
            const statusResponse = await axios.get(
                `${splunkBaseUrl}/services/search/jobs/${sid}`,
                { headers: getAuthHeaders(), httpsAgent, params: { output_mode: 'json' } }
            );
            const dispatchState = statusResponse.data.entry?.[0]?.content?.dispatchState;
            log(`Job status: ${dispatchState}`, { attempts });
            isDone = dispatchState === 'DONE' || dispatchState === 'FAILED';
            attempts++;
        }

        const resultsResponse = await axios.get(
            `${splunkBaseUrl}/services/search/jobs/${sid}/results`,
            { headers: getAuthHeaders(), httpsAgent, params: { output_mode: 'json', count: 100 } }
        );

        const results = resultsResponse.data.results || [];
        log('Search completed', { resultCount: results.length });
        res.json({ status: 'success', sid, query, resultCount: results.length, results });
    } catch (error) {
        log('Search failed', { error: error.message });
        res.status(500).json({ status: 'error', message: error.message, query });
    }
});

app.get('/api/splunk/alerts', async (req, res) => {
    log('Fetching alerts...');
    try {
        const response = await axios.get(
            `${splunkBaseUrl}/services/alerts/fired_alerts`,
            { headers: getAuthHeaders(), httpsAgent, params: { output_mode: 'json', count: 50 } }
        );
        const alerts = response.data.entry || [];
        log('Alerts fetched', { count: alerts.length });
        res.json({
            status: 'success',
            alertCount: alerts.length,
            alerts: alerts.map(a => ({
                name: a.name,
                severity: a.content?.severity || 'unknown',
                triggered: a.content?.triggered_time || 'unknown'
            }))
        });
    } catch (error) {
        log('Failed to fetch alerts', { error: error.message });
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.get('/api/mcp/tools', (req, res) => {
    log('MCP tools requested');
    res.json({
        tools: [
            { name: 'splunk_search', description: 'Execute a Splunk SPL query', parameters: { query: { type: 'string', required: true }, earliest_time: { type: 'string', default: '-24h' }, latest_time: { type: 'string', default: 'now' } } },
            { name: 'splunk_alerts', description: 'Get fired alerts from Splunk', parameters: {} },
            { name: 'splunk_test', description: 'Test Splunk connectivity', parameters: {} }
        ]
    });
});

app.post('/api/mcp/execute', async (req, res) => {
    const { tool, parameters } = req.body;
    log('MCP tool execution', { tool, parameters });

    try {
        let result;
        switch (tool) {
            case 'splunk_search':
                const searchRes = await axios.post(`http://localhost:${config.nodePort}/api/splunk/search`, parameters);
                result = searchRes.data;
                break;
            case 'splunk_alerts':
                const alertsRes = await axios.get(`http://localhost:${config.nodePort}/api/splunk/alerts`);
                result = alertsRes.data;
                break;
            case 'splunk_test':
                const testRes = await axios.get(`http://localhost:${config.nodePort}/api/splunk/test`);
                result = testRes.data;
                break;
            default:
                return res.status(400).json({ error: `Unknown tool: ${tool}` });
        }
        res.json({ status: 'success', tool, result });
    } catch (error) {
        log('Tool execution failed', { error: error.message });
        res.status(500).json({ status: 'error', tool, message: error.message });
    }
});

// --- Native Splunk MCP ---

function getMcpAuthHeaders() {
    if (config.splunkToken) {
        return { 'Authorization': `Bearer ${config.splunkToken}` };
    }
    const auth = Buffer.from(`${config.splunkUsername}:${config.splunkPassword}`).toString('base64');
    return { 'Authorization': `Basic ${auth}` };
}

app.get('/api/native-mcp/test', async (req, res) => {
    log('Testing native Splunk MCP connectivity...');
    try {
        const response = await axios.get(config.splunkMcpEndpoint, {
            headers: { ...getMcpAuthHeaders(), 'Accept': 'application/json' },
            httpsAgent
        });
        log('Native MCP connection successful', response.data);
        res.json({ status: 'connected', endpoint: config.splunkMcpEndpoint, response: response.data });
    } catch (error) {
        log('Native MCP connection failed', { error: error.message, code: error.code });
        res.status(500).json({ status: 'error', endpoint: config.splunkMcpEndpoint, message: error.message, hint: 'Check MCP token and endpoint' });
    }
});

app.get('/api/native-mcp/tools', async (req, res) => {
    log('Fetching native MCP tools...');
    try {
        const response = await axios.get(`${config.splunkMcpEndpoint}/tools`, {
            headers: { ...getMcpAuthHeaders(), 'Accept': 'application/json' },
            httpsAgent
        });
        log('Native MCP tools fetched', response.data);
        res.json(response.data);
    } catch (error) {
        log('Failed to fetch native MCP tools', { error: error.message });
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.post('/api/native-mcp/execute', async (req, res) => {
    const { tool, arguments: args } = req.body;
    log('Executing native MCP tool', { tool, args });
    try {
        const response = await axios.post(`${config.splunkMcpEndpoint}/tools/${tool}`, args, {
            headers: { ...getMcpAuthHeaders(), 'Content-Type': 'application/json', 'Accept': 'application/json' },
            httpsAgent
        });
        log('Native MCP tool executed', response.data);
        res.json({ status: 'success', tool, result: response.data });
    } catch (error) {
        log('Native MCP tool execution failed', { error: error.message });
        res.status(500).json({ status: 'error', tool, message: error.message });
    }
});

app.get('/api/mcp/config', (req, res) => {
    log('MCP config requested');
    res.json({
        mcpServers: {
            "splunk-mcp-server": {
                command: "npx",
                args: ["-y", "mcp-remote", config.splunkMcpEndpoint, "--header", `Authorization: Bearer ${config.splunkToken ? '<token-configured>' : '<no-token>'}`]
            }
        }
    });
});

app.listen(config.nodePort, () => {
    console.log(`[*] Splunk MCP Connector running on port ${config.nodePort}`);
    console.log(`[+] Splunk: ${splunkBaseUrl} | Auth: ${config.splunkToken ? 'Token' : 'Basic'} | SSL: ${config.verifySsl}`);
});
