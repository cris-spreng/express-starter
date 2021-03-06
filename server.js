const express = require('express');
const bodyParser = require('body-parser');
const winston = require('winston');
const expressWinston = require('express-winston');
const http = require('http');
const dotenv = require('dotenv').config();
const helmet = require('helmet');
const mongoose = require('mongoose');
const cors = require('cors');

// Rutas
// Cargamos las rutas de nuestros usuarios
const usersRoutes = require('./src/api/routes/users');

// Definición de variables de entorno
const port = process.env.PORT || 8000;

// Monto el app en express
const app = express();

// Middlewares
// Habilito el parseo de x-url-encoded-form de manera extendida
app.use(bodyParser.urlencoded({ extended: true }));
// Habilito el parseo de las peticiones en json
app.use(bodyParser.json());

// Protección de cabeceras
app.use(helmet());

// CORS
app.use(cors());

// Logger
/* app.use(
  expressWinston.logger({
    transports: [new winston.transports.Console()],
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.json(),
    ),
    meta: true, // optional: control whether you want to log the meta data about the request (default to true)
    msg: 'HTTP {{req.method}} {{req.url}}', // optional: customize the default logging message. E.g. "{{res.statusCode}} {{req.method}} {{res.responseTime}}ms {{req.url}}"
    expressFormat: true, // Use the default Express/morgan request formatting. Enabling this will override any msg if true. Will only output colors with colorize set to true
    colorize: false, // Color the text and status code, using the Express/morgan color palette (text: gray, status: default green, 3XX cyan, 4XX yellow, 5XX red).
    ignoreRoute: () => {
      return false;
    }, // optional: allows to skip some log messages based on request and/or response
  }),
); */

// Hola mundo en express
//app.use('/api/v1', (_, res) => res.status(200).json({ hola: 'mundo' }));

//bodyParser no envía body al endpoint si no configuramos esto y el body llega vacío a users
app.use(express.json());

// Agregamos la ruta de users a nuestra API
app.use('/api/v1/users', usersRoutes);

// Configuración de la base de datos
mongoose.set('useCreateIndex', true);

// Nos conectamos a las base de datos en mongo
mongoose.connect(process.env.MONGO_DB_URI_DEV,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
);

// Creo el servidor con nodejs (http module)
const server = http.createServer(app);

// Escucho el servidor
server.listen(port);
console.log(`Corriendo servidor en http://localhost:${port}`);

module.exports = app;
