require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const routes = require('./routes');

const app = express();
// body-parser middleware'i kullanarak gelen JSON verileri ayrıştırılır
app.use(bodyParser.json());

//middleware mantığında /api altonda gelen istekleri routelerde birleştirecek laraveldeki prefix gibi
app.use('/api', routes); 

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
