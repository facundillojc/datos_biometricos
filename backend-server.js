// backend-server.js - Servidor Express con WebAuthn mejorado con logs
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');

const app = express();
const port = 5000;
const rpName = 'Aplicación Segura';
const rpID = 'localhost';
const origin = `http://${rpID}:${port}`;

const userDB = {
  users: {
    'admin': {
      id: 'admin',
      password: 'admin',
      name: 'Administrador',
      authenticators: []
    }
  }
};

app.use(cors({
  origin: ['http://localhost:5000', 'http://127.0.0.1:5000'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(session({
  secret: 'tu-clave-secreta-muy-segura',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.use(express.static('public'));

const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    console.log(`Usuario autenticado: ${req.session.userId}`);
    next();
  } else {
    console.log('Acceso denegado: Usuario no autenticado');
    res.status(401).json({ error: 'No autenticado' });
  }
};

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`Intento de inicio de sesión para ${username}`);

  const user = userDB.users[username];
  if (user && user.password === password) {
    req.session.userId = user.id;
    console.log(`Login exitoso para ${username}`);
    res.json({ success: true, user: { id: user.id, name: user.name, hasBiometrics: user.authenticators.length > 0 } });
  } else {
    console.log(`Fallo de autenticación para ${username}`);
    res.status(401).json({ success: false, error: 'Credenciales inválidas' });
  }
});

app.get('/api/webauthn/status', isAuthenticated, (req, res) => {
  const user = userDB.users[req.session.userId];
  res.json({ hasBiometrics: user.authenticators.length > 0 });
});

app.listen(port, () => {
  console.log(`Servidor funcionando en http://localhost:${port}`);
});
