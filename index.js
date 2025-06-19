const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 8000;
const apiPrefix = '/api';
const secretKey = 'SECRET_KEY'; // ⚠️ Cámbiala en producción

// Middlewares
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Conexión a MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'reservas'
});

db.connect(err => {
  if (err) {
    console.error('❌ Error al conectar con la base de datos:', err.message);
  } else {
    console.log('✅ Conectado a la base de datos "reservas"');
  }
});



 // get para usuarios
app.get(`${apiPrefix}/usuarios`, (req, res) => {
  const sql = 'SELECT * FROM usuarios';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('❌ Error al obtener usuarios:', err.message);
      return res.status(500).json({ error: 'Error al obtener usuarios' });
    }
    res.json(results);
  });
});

//get para reservas
app.get(`${apiPrefix}/reservas`, (req, res) => {
  const sql = `
    SELECT r.id, r.fecha_reserva, u.nombre AS usuario, v.destino AS vuelo
    FROM reservas r
    INNER JOIN usuarios u ON r.id_usuario = u.id
    INNER JOIN vuelos v ON r.id_vuelo = v.id
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('❌ Error al obtener reservas:', err.message);
      return res.status(500).json({ error: 'Error al obtener reservas' });
    }
    res.json(results);
  });
});


// ==============================
// POST: Crear nuevo usuario
// ==============================


app.post(`${apiPrefix}/usuarios`, async (req, res) => {
  const { nombre, email, password, id_rol } = req.body;

  if (!nombre || !email || !password || !id_rol) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const sql = `
    INSERT INTO usuarios (nombre, email, password, id_rol)
    VALUES (?, ?, ?, ?)
  `;

  db.query(sql, [nombre, email, hashedPassword, id_rol], (err, result) => {
    if (err) {
      console.error('❌ Error al registrar usuario:', err.message);
      return res.status(500).json({ error: 'Error al registrar usuario' });
    }
    res.status(201).json({ mensaje: '✅ Usuario registrado correctamente', id: result.insertId });
  });
});




// ==============================
// GET: Listar usuarios con rol
// ==============================
app.get(`${apiPrefix}/usuarios`, (req, res) => {
  const sql = `
    SELECT u.id, u.nombre, u.email, r.nombre AS rol
    FROM usuarios u
    INNER JOIN roles r ON u.id_rol = r.id
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('❌ Error al obtener usuarios:', err.message);
      return res.status(500).json({ error: 'Error al obtener usuarios' });
    }
    res.json(results);
  });
});


// ==============================
// POST: Login de usuario
// ==============================
app.post(`${apiPrefix}/login`, (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
  }

  const sql = `SELECT * FROM usuarios WHERE email = ?`;
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error('❌ Error en la consulta:', err.message);
      return res.status(500).json({ error: 'Error en el servidor' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const usuario = results[0];
    const match = await bcrypt.compare(password, usuario.password);

    if (!match) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ id: usuario.id, rol: usuario.id_rol }, SECRET_KEY, {
      expiresIn: '1h'
    });

    // Guardar el token en la base de datos
    const expira = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
    const insertarToken = `INSERT INTO tokens (id_usuario, token, fecha_expiracion) VALUES (?, ?, ?)`;

    db.query(insertarToken, [usuario.id, token, expira], (err2) => {
      if (err2) {
        console.error('❌ Error al guardar el token:', err2.message);
        return res.status(500).json({ error: 'Error al guardar el token' });
      }

      res.status(200).json({
        mensaje: '✅ Login exitoso',
        token,
        usuario: {
          id: usuario.id,
          nombre: usuario.nombre,
          email: usuario.email,
          id_rol: usuario.id_rol
        }
      });
    });
  });
});

// METODO GET PARA OBTENER VUELOS
app.get(`${apiPrefix}/vuelos`, (req, res) => {
  const sql = 'SELECT * FROM vuelos';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('❌ Error al obtener vuelos:', err.message);
      return res.status(500).json({ error: 'Error al obtener vuelos' });
    }
    res.json(results);
  });
});

// ==============================
// Servidor iniciado
// ==============================
app.listen(PORT, () => {
  console.log(`🚀 API corriendo en http://localhost:${PORT}`);
});
