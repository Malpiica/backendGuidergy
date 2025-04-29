require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Manejador de errores global
process.on('uncaughtException', (err) => {
  console.error('Error no capturado:', err);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('Promesa rechazada no manejada:', err);
  process.exit(1);
});

try {
  // Verificar variables de entorno
  console.log('Verificando variables de entorno...');
  console.log('DB_HOST:', process.env.DB_HOST);
  console.log('DB_NAME:', process.env.DB_NAME);
  console.log('DB_USER:', process.env.DB_USER);
  console.log('DB_PORT:', process.env.DB_PORT);

  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json());

  // Security middleware
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  // Database configuration
  console.log('Configurando conexión a la base de datos...');
  const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: process.env.DB_CONNECTION_LIMIT,
    queueLimit: 0,
    ssl: {
      rejectUnauthorized: false
    }
  });

  // Verificar conexión a la base de datos
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error al conectar con la base de datos:', err);
      process.exit(1);
    }
    console.log('Conexión a la base de datos establecida correctamente');
    connection.release();
  });

  // Health check route for database connection
  app.get('/api/health/db', (req, res) => {
    pool.getConnection((err, connection) => {
      if (err) {
        console.error('Error de conexión a la base de datos:', err);
        return res.status(500).json({
          status: 'error',
          message: 'Error al conectar con la base de datos',
          error: err.message
        });
      }
      connection.query('SELECT 1', (queryErr) => {
        connection.release();
        if (queryErr) {
          console.error('Error en la consulta de prueba:', queryErr);
          return res.status(500).json({
            status: 'error',
            message: 'Error en la consulta de prueba',
            error: queryErr.message
          });
        }
        res.json({
          status: 'success',
          message: 'Conexión a la base de datos establecida correctamente'
        });
      });
    });
  });

  // Configuración de JWT
  const JWT_SECRET = process.env.JWT_SECRET || 'tu-secreto-seguro-aqui';
  const JWT_EXPIRES_IN = '24h';

  // Middleware para verificar el token JWT
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Token no proporcionado' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Token inválido' });
      }
      req.user = user;
      next();
    });
  };

  // Ruta para registrar una nueva comercializadora
  app.post('/api/register/comercializadora', authenticateToken, async (req, res) => {
    try {
      const { nombre, archivo } = req.body;

      if (!nombre || !archivo) {
        return res.status(400).json({ 
          status: 'error',
          message: 'Todos los campos son requeridos'
        });
      }

      // Verificar si el archivo es CSV o Excel
      const allowedTypes = [
        'text/csv',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      ];

      const fileType = archivo.split(';')[0].split(':')[1];
      if (!allowedTypes.includes(fileType)) {
        return res.status(400).json({
          status: 'error',
          message: 'Solo se permiten archivos CSV o Excel'
        });
      }

      // Verificar si el usuario es maestro
      if (req.user.role !== 'maestro') {
        return res.status(403).json({
          status: 'error',
          message: 'Solo los maestros pueden registrar comercializadoras'
        });
      }

      // Verificar si ya existe una comercializadora con el mismo nombre
      const [existing] = await pool.promise().query(
        'SELECT * FROM comercializadora WHERE nombre = ?',
        [nombre]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          status: 'error',
          message: 'Ya existe una comercializadora con ese nombre'
        });
      }

      // Insertar la nueva comercializadora
      const [result] = await pool.promise().query(
        'INSERT INTO comercializadora (nombre, archivo, id_maestro) VALUES (?, ?, ?)',
        [nombre, archivo, req.user.id]
      );

      res.status(201).json({
        status: 'success',
        message: 'Comercializadora registrada exitosamente',
        data: {
          id: result.insertId,
          nombre
        }
      });
    } catch (error) {
      console.error('Error al registrar comercializadora:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al registrar la comercializadora'
      });
    }
  });

  // Route to register a new maestro
  app.post('/api/register/maestro', async (req, res) => {
    const { nombre, apellidos, username, email, password } = req.body;

    // Validar que todos los campos estén presentes
    if (!nombre || !apellidos || !username || !email || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Todos los campos son obligatorios'
      });
    }

    try {
      // Verificar si ya existe un usuario con ese username o email
      const [existing] = await pool.promise().query(
        'SELECT id_maestro FROM maestro WHERE username = ? OR email = ?',
        [username, email]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          status: 'error',
          message: 'El usuario ya existe con ese email o username'
        });
      }

      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insertar nuevo maestro
      const [result] = await pool.promise().query(
        `INSERT INTO maestro (nombre, apellidos, username, email, password) 
         VALUES (?, ?, ?, ?, ?)`,
        [nombre, apellidos, username, email, hashedPassword]
      );

      res.status(201).json({
        status: 'success',
        message: 'Maestro registrado correctamente',
        data: {
          id_maestro: result.insertId,
          nombre,
          apellidos,
          username,
          email
        }
      });
    } catch (error) {
      console.error('Error al registrar maestro:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al registrar al maestro',
        error: error.message
      });
    }
  });

  // Route to login
  app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Todos los campos son obligatorios'
      });
    }

    try {
      // Buscar en la tabla maestro
      const [maestros] = await pool.promise().query(
        'SELECT * FROM maestro WHERE username = ?',
        [username]
      );

      // Buscar en la tabla administrador
      const [administradores] = await pool.promise().query(
        'SELECT * FROM administrador WHERE username = ?',
        [username]
      );

      // Buscar en la tabla usuario_basico
      const [usuariosBasicos] = await pool.promise().query(
        'SELECT * FROM usuario_basico WHERE username = ?',
        [username]
      );

      let user = null;
      let role = null;

      // Verificar en maestro
      if (maestros.length > 0) {
        const maestro = maestros[0];
        const isValidPassword = await bcrypt.compare(password, maestro.password);
        if (isValidPassword) {
          user = maestro;
          role = 'maestro';
        }
      }

      // Verificar en administrador
      if (!user && administradores.length > 0) {
        const administrador = administradores[0];
        const isValidPassword = await bcrypt.compare(password, administrador.password);
        if (isValidPassword) {
          user = administrador;
          role = 'administrador';
        }
      }

      // Verificar en usuario_basico
      if (!user && usuariosBasicos.length > 0) {
        const usuarioBasico = usuariosBasicos[0];
        const isValidPassword = await bcrypt.compare(password, usuarioBasico.password);
        if (isValidPassword) {
          user = usuarioBasico;
          role = 'usuario_basico';
        }
      }

      if (!user) {
        return res.status(401).json({
          status: 'error',
          message: 'Credenciales inválidas'
        });
      }

      // Crear token JWT
      const token = jwt.sign(
        { 
          id: user.id_maestro || user.id_administrador || user.id_usuario_basico,
          username: user.username,
          role: role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Eliminar la contraseña del objeto de respuesta
      delete user.password;

      res.status(200).json({
        status: 'success',
        message: 'Login exitoso',
        data: {
          token,
          user: {
            id: user.id_maestro || user.id_administrador || user.id_usuario_basico,
            nombre: user.nombre || user.titular,
            apellidos: user.apellidos || '',
            username: user.username,
            email: user.email,
            role: role
          }
        }
      });
    } catch (error) {
      console.error('Error al hacer login:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al iniciar sesión',
        error: error.message
      });
    }
  });

  // Ruta protegida de ejemplo
  app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
      const [users] = await pool.promise().query(
        'SELECT id_maestro, nombre, apellidos, username, email FROM maestro WHERE id_maestro = ?',
        [req.user.id]
      );

      if (users.length === 0) {
        return res.status(404).json({
          status: 'error',
          message: 'Usuario no encontrado'
        });
      }

      res.status(200).json({
        status: 'success',
        data: users[0]
      });
    } catch (error) {
      res.status(500).json({
        status: 'error',
        message: 'Error al obtener el perfil',
        error: error.message
      });
    }
  });

  // Ruta para registrar un nuevo administrador
  app.post('/api/register/administrador', authenticateToken, async (req, res) => {
    try {
      const { 
        titular, 
        telefono, 
        nif_cif, 
        email, 
        direccion, 
        cp, 
        localidad, 
        provincia, 
        username, 
        password, 
        margen,
        id_comercializadora 
      } = req.body;

      // Validar campos requeridos
      if (!titular || !telefono || !nif_cif || !email || !direccion || !cp || 
          !localidad || !provincia || !username || !password || !margen || !id_comercializadora) {
        return res.status(400).json({ 
          status: 'error',
          message: 'Todos los campos son requeridos'
        });
      }

      // Verificar si el usuario es maestro
      if (req.user.role !== 'maestro') {
        return res.status(403).json({
          status: 'error',
          message: 'Solo los maestros pueden registrar administradores'
        });
      }

      // Verificar si ya existe un administrador con el mismo username, email o nif_cif
      const [existing] = await pool.promise().query(
        'SELECT * FROM administrador WHERE username = ? OR email = ? OR nif_cif = ?',
        [username, email, nif_cif]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          status: 'error',
          message: 'Ya existe un administrador con ese username, email o NIF/CIF'
        });
      }

      // Verificar si la comercializadora existe
      const [comercializadora] = await pool.promise().query(
        'SELECT * FROM comercializadora WHERE id_comercializadora = ?',
        [id_comercializadora]
      );

      if (comercializadora.length === 0) {
        return res.status(404).json({
          status: 'error',
          message: 'La comercializadora seleccionada no existe'
        });
      }

      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // Iniciar transacción
      const connection = await pool.promise().getConnection();
      await connection.beginTransaction();

      try {
        // Insertar el nuevo administrador
        const [result] = await connection.query(
          `INSERT INTO administrador (
            titular, telefono, nif_cif, email, direccion, cp, 
            localidad, provincia, username, password, margen, id_maestro
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            titular, telefono, nif_cif, email, direccion, cp,
            localidad, provincia, username, hashedPassword, margen, req.user.id
          ]
        );

        // Crear la relación en administrador_comercializadora
        await connection.query(
          'INSERT INTO administrador_comercializadora (id_administrador, id_comercializadora) VALUES (?, ?)',
          [result.insertId, id_comercializadora]
        );

        // Confirmar transacción
        await connection.commit();

        res.status(201).json({
          status: 'success',
          message: 'Administrador registrado exitosamente',
          data: {
            id: result.insertId,
            titular,
            email
          }
        });
      } catch (error) {
        // Revertir transacción en caso de error
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('Error al registrar administrador:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al registrar el administrador'
      });
    }
  });

  // Ruta para obtener las comercializadoras
  app.get('/api/comercializadoras', authenticateToken, async (req, res) => {
    try {
      // Verificar si el usuario es maestro
      if (req.user.role !== 'maestro') {
        return res.status(403).json({
          status: 'error',
          message: 'Solo los maestros pueden ver las comercializadoras'
        });
      }

      const [comercializadoras] = await pool.promise().query(
        'SELECT id_comercializadora, nombre FROM comercializadora WHERE id_maestro = ?',
        [req.user.id]
      );

      res.json({
        status: 'success',
        data: comercializadoras
      });
    } catch (error) {
      console.error('Error al obtener comercializadoras:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al obtener las comercializadoras'
      });
    }
  });

  // Endpoint para verificar si un usuario es maestro
  app.get('/api/auth/check-maestro', authenticateToken, async (req, res) => {
    try {
      const [result] = await pool.promise().query(
        'SELECT id_maestro FROM maestro WHERE username = ?',
        [req.user.username]
      );

      res.json({ isMaestro: result.length > 0 });
    } catch (error) {
      res.status(500).json({ message: 'Error al verificar si es maestro' });
    }
  });

  // Endpoint para verificar si un usuario es administrador
  app.get('/api/auth/check-admin', authenticateToken, async (req, res) => {
    try {
      const [result] = await pool.promise().query(
        `SELECT a.id_administrador 
         FROM administrador a 
         JOIN maestro m ON a.id_maestro = m.id_maestro 
         WHERE m.username = ?`,
        [req.user.username]
      );

      res.json({ isAdmin: result.length > 0 });
    } catch (error) {
      res.status(500).json({ message: 'Error al verificar si es administrador' });
    }
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
} catch (error) {
  console.error('Error al iniciar el servidor:', error);
  process.exit(1);
}