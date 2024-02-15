const express = require('express');
const bodyParser = require('body-parser');

let requests = [];

const app = express();

app.use(bodyParser.json());

app.get('/requests', (req, res) => {
    res.json(requests);
});

app.get('/requests/:id', (req, res) => {
    const requestId = req.params.id;
    const request = requests.find(item => item.id === requestId);
    if (request) {
        res.json(request);
    } else {
        res.status(404).json({ error: 'Request not found' });
    }
});

app.post('/repeat/:id', (req, res) => {
    const requestId = req.params.id;
    const request = requests.find(item => item.id === requestId);

    res.json({ message: 'Request repeated successfully' });
});

app.post('/scan/:id', (req, res) => {
    const requestId = req.params.id;
    const request = requests.find(item => item.id === requestId);
    
    res.json({ message: 'Request scanned successfully' });
});

const PORT = 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});