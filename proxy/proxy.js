const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const url = require('url');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = 8080;

const key = fs.readFileSync('cert.key');
const cert = fs.readFileSync('certs/yngwie.ru.crt');
const credentials = { key: key, cert: cert };

mongoose.connect(mongoUrl, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
const db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));

db.once('open', function() {
  console.log('Connected to MongoDB');
});

const dataSchema = new mongoose.Schema({
    name: String,
    description: String
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use((req, res) => {
    const requestObject = {
        method: req.method,
        path: req.path,
        get_params: req.query,
        headers: req.headers,
        cookies: parseCookies(req),
        post_params: req.body,
        timestamp: new Date()
    };
    // todo
    // check on vunerabilities
    // save to db

    const { hostname, port } = url.parse(req.url);

    const isHttps = req.protocol === 'https';
    const proxy = isHttps ? https : http;

    const options = {
        hostname: hostname,
        port: port || (isHttps ? 443 : 80),
        path: req.url,
        method: req.method,
        headers: req.headers
    };

    const proxyRequest = proxy.request(options, (proxyResponse) => {
        let responseBody = '';
        proxyResponse.on('data', (chunk) => {
            responseBody += chunk;
        });
        proxyResponse.on('end', () => {
            const responseObject = {
                code: proxyResponse.statusCode,
                message: proxyResponse.statusMessage,
                headers: proxyResponse.headers,
                body: responseBody,
                timestamp: new Date()
            };
            // todo
            // save to db
        });

        res.writeHead(proxyResponse.statusCode, proxyResponse.statusMessage, proxyResponse.headers);
        proxyResponse.pipe(res);
    });

    if (req.method !== 'GET' && req.method !== 'HEAD') {
        req.pipe(proxyRequest);
    } else {
        proxyRequest.end();
    }
});

const httpServer = http.createServer(app);
const httpsServer = https.createServer(credentials, app);

httpServer.listen(PORT, () => {
    console.log(`HTTP Proxy Server running on port ${PORT}`);
});

httpsServer.listen(443, () => {
    console.log('HTTPS Proxy Server running on port 443');
});
