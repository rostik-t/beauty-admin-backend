const express = require('express');
const CloudCustomersAPI = require('./cloud-customers-api');

const app = express();
const port = 3000;

require('dotenv').config();

const cloudCustomersAPI = new CloudCustomersAPI();

app.use(express.json());
app.use('/api', cloudCustomersAPI.getRouter());

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
