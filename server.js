require('dotenv').config();
const express = require('express');
const sqlite3 = require('@libsql/sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = parseInt(process.env.NIVEL_ENCRIPTACION) || 10;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. Extraemos las variables
const dbUrl = process.env.TURSO_DATABASE_URL;
const dbToken = process.env.TURSO_AUTH_TOKEN;

// 2. Conectamos con el formato estricto de Vercel/Turso
let conexionTurso = "";
if (dbUrl && dbToken) {
  conexionTurso = `${dbUrl}?authToken=${dbToken}`;
} else {
  console.error("ADVERTENCIA: Las variables de Turso no están cargando en Vercel.");
}

const db = new sqlite3.Database(conexionTurso, (err) => {
  if (err) console.error('Error al conectar a Turso:', err.message);
  else console.log('Conectado a la base de datos de Turso en la nube.');
});

// Inicialización de Tablas
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    rol TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS mecanicos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    especialidad TEXT,
    telefono TEXT,
    usuario_id INTEGER,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ordenes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT,
    nombre_cliente TEXT,
    nit TEXT,
    telefono TEXT,
    placa TEXT,
    marca TEXT,
    modelo TEXT,
    color TEXT,
    mecanico TEXT,
    accesorios TEXT,
    fallas TEXT,
    observaciones TEXT,
    estado TEXT DEFAULT 'Pendiente'
  )`);

  // Migración automática: Agrega la columna estado si la tabla ya existía sin ella
  db.run(`ALTER TABLE ordenes ADD COLUMN estado TEXT DEFAULT 'Pendiente'`, (err) => {
    // Si la columna ya existe, SQLite arroja error (duplicate column name), el cual se ignora deliberadamente
  });
});

// Endpoint: Verificar si es la primera vez que se abre el sistema
app.get('/api/setup/check', (req, res) => {
  db.get(`SELECT COUNT(*) as count FROM usuarios`, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ setupNeeded: row.count === 0 });
  });
});

// Endpoint: Crear el primer administrador (Dueño)
app.post('/api/setup', async (req, res) => {
  const { username, password } = req.body;
  
  db.get(`SELECT COUNT(*) as count FROM usuarios`, async (err, row) => {
    if (err) return res.status(500).json({ exito: false, mensaje: err.message });
    if (row.count > 0) return res.status(403).json({ exito: false, mensaje: 'El sistema ya ha sido configurado.' });
    
    try {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      db.run(`INSERT INTO usuarios (username, password, rol) VALUES (?, ?, 'Dueño')`, [username, hashedPassword], function(err2) {
        if (err2) return res.status(500).json({ exito: false, mensaje: err2.message });
        res.json({ exito: true, mensaje: 'Administrador configurado exitosamente. Ahora puedes iniciar sesión.' });
      });
    } catch (error) {
      res.status(500).json({ exito: false, mensaje: 'Error al encriptar la contraseña.' });
    }
  });
});

// Endpoint: Inicio de sesión
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  const sql = `SELECT id, username, password, rol FROM usuarios WHERE username = ?`;
  
  db.get(sql, [username], async (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (!row) {
      return res.json({ exito: false, mensaje: 'Usuario o contraseña incorrectos' });
    }

    try {
      const match = await bcrypt.compare(password, row.password);
      
      if (match) {
        delete row.password; 
        res.json({ exito: true, usuario: row, mensaje: 'Inicio de sesión correcto' });
      } else {
        res.json({ exito: false, mensaje: 'Usuario o contraseña incorrectos' });
      }
    } catch (error) {
      res.status(500).json({ exito: false, mensaje: 'Error en la validación.' });
    }
  });
});

// Endpoint: Actualizar la contraseña del usuario activo
app.put('/api/perfil', async (req, res) => {
  const { id, newPassword } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    db.run(`UPDATE usuarios SET password = ? WHERE id = ?`, [hashedPassword, id], function(err) {
      if (err) return res.status(500).json({ exito: false, mensaje: err.message });
      res.json({ exito: true, mensaje: 'Contraseña actualizada correctamente.' });
    });
  } catch (error) {
    res.status(500).json({ exito: false, mensaje: 'Error al encriptar la nueva contraseña.' });
  }
});

// Endpoint: Obtener Mecánicos
app.get('/api/mecanicos', (req, res) => {
  const sql = `
    SELECT m.id, m.nombre, m.especialidad, m.telefono, u.username 
    FROM mecanicos m
    LEFT JOIN usuarios u ON m.usuario_id = u.id
    ORDER BY m.nombre ASC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Endpoint: Crear Trabajador + Usuario
app.post('/api/usuarios', async (req, res) => {
  const { nombre, especialidad, telefono, username, password, rol } = req.body;

  if (!username || !password || !rol || !nombre || !especialidad || !telefono) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const sqlUser = `INSERT INTO usuarios (username, password, rol) VALUES (?, ?, ?)`;
    db.run(sqlUser, [username, hashedPassword, rol], function(err) {
      if (err) return res.status(400).json({ error: 'El nombre de usuario ya está registrado, elija otro' });
      
      const usuario_id = this.lastID; 
      const sqlMec = `INSERT INTO mecanicos (nombre, especialidad, telefono, usuario_id) VALUES (?, ?, ?, ?)`;
      
      db.run(sqlMec, [nombre, especialidad, telefono, usuario_id], function(err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ exito: true, mensaje: 'Personal y usuario de sistema registrados exitosamente' });
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al procesar la seguridad' });
  }
});

// Endpoint: Registrar Orden
app.post('/api/ordenes', (req, res) => {
  const { 
    fecha, nombre_cliente, nit, telefono, 
    placa, marca, modelo, color, mecanico, 
    accesorios, fallas, observaciones 
  } = req.body;

  const sql = `INSERT INTO ordenes 
    (fecha, nombre_cliente, nit, telefono, placa, marca, modelo, color, mecanico, accesorios, fallas, observaciones) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  const params = [fecha, nombre_cliente, nit, telefono, placa, marca, modelo, color, mecanico, accesorios, fallas, observaciones];

  db.run(sql, params, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ exito: true, id_orden: this.lastID, mensaje: 'Orden de trabajo guardada correctamente' });
  });
});


// Endpoint: Actualizar estado de una orden (Marcar como Entregado / Pendiente)
app.put('/api/ordenes/:id/estado', (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;
  const nuevoEstado = estado || 'Entregado';

  const sql = `UPDATE ordenes SET estado = ? WHERE id = ?`;
  db.run(sql, [nuevoEstado, id], function(err) {
    if (err) return res.status(500).json({ exito: false, error: err.message });
    if (this.changes === 0) return res.status(404).json({ exito: false, mensaje: 'Orden no encontrada' });
    res.json({ exito: true, mensaje: `Orden #${id} marcada como ${nuevoEstado} exitosamente` });
  });
});

// Endpoint: Marcar orden como Entregada (PUT o POST)
app.put('/api/ordenes/:id/entregar', (req, res) => {
  const { id } = req.params;
  const sql = `UPDATE ordenes SET estado = 'Entregado' WHERE id = ?`;
  db.run(sql, [id], function(err) {
    if (err) return res.status(500).json({ exito: false, error: err.message });
    if (this.changes === 0) return res.status(404).json({ exito: false, mensaje: 'Orden no encontrada' });
    res.json({ exito: true, mensaje: `Orden #${id} marcada como Entregado exitosamente` });
  });
});

app.post('/api/ordenes/:id/entregar', (req, res) => {
  const { id } = req.params;
  const sql = `UPDATE ordenes SET estado = 'Entregado' WHERE id = ?`;
  db.run(sql, [id], function(err) {
    if (err) return res.status(500).json({ exito: false, error: err.message });
    if (this.changes === 0) return res.status(404).json({ exito: false, mensaje: 'Orden no encontrada' });
    res.json({ exito: true, mensaje: `Orden #${id} marcada como Entregado exitosamente` });
  });
});

// Endpoint: Obtener Órdenes
app.get('/api/ordenes', (req, res) => {
  db.all(`SELECT * FROM ordenes ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const ordenes = (rows || []).map(row => ({
      ...row,
      estado: row.estado || 'Pendiente'
    }));
    res.json(ordenes);
  });
});

// Endpoint: Conteo agrupado de vehículos por mecánico (Gráfica de pastel - Solo Pendientes)
app.get('/api/grafica/vehiculos-mecanicos', (req, res) => {
  const sql = `
    SELECT COALESCE(NULLIF(TRIM(mecanico), ''), 'Sin asignar') AS mecanico, COUNT(*) AS total
    FROM ordenes
    WHERE estado IS NULL OR estado != 'Entregado'
    GROUP BY mecanico
    ORDER BY total DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      const sqlFallback = `
        SELECT COALESCE(NULLIF(TRIM(mecanico), ''), 'Sin asignar') AS mecanico, COUNT(*) AS total
        FROM ordenes
        GROUP BY mecanico
        ORDER BY total DESC
      `;
      return db.all(sqlFallback, [], (err2, rowsFallback) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json(rowsFallback || []);
      });
    }
    res.json(rows || []);
  });
});

// Solo encendemos el puerto si estamos en tu computadora (desarrollo local)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
  });
}

// Exportamos la app para que Vercel la controle
module.exports = app;
//Prueba