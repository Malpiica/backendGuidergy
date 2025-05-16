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
  // Permitir múltiples orígenes en CORS
  const allowedOrigins = [
    'http://localhost:5173',
    'https://guidergy.com',
    'http://guidergy.com',
    'https://backendguidergy-production.up.railway.app',
    'http://backendguidergy-production.up.railway.app'
  ];
  app.use(cors({
    origin: function (origin, callback) {
      // Permitir peticiones sin origen (como Postman o curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true
  }));

  // Evitar redirecciones en OPTIONS
  app.options('*', cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true
  }));
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
  const JWT_SECRET = process.env.JWT_SECRET
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

  // Endpoint para obtener todas las comercializadoras
  app.get('/api/comercializadoras', authenticateToken, async (req, res) => {
    try {
      const [comercializadoras] = await pool.promise().query('SELECT id_comercializadora, nombre FROM comercializadora');
      res.json({
        status: 'success',
        data: comercializadoras
      });
    } catch (error) {
      console.error('Error al obtener comercializadoras:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al obtener las comercializadoras',
        error: error.message
      });
    }
  });

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

  // Endpoint para registrar un usuario básico (solo administradores)
  app.post('/api/register/usuario-basico', authenticateToken, async (req, res) => {
    try {
      if (req.user.role !== 'administrador') {
        return res.status(403).json({
          status: 'error',
          message: 'Solo los administradores pueden registrar usuarios básicos'
        });
      }
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
        margen
      } = req.body;
      if (!titular || !telefono || !nif_cif || !email || !direccion || !cp || !localidad || !provincia || !username || !password || margen === undefined) {
        return res.status(400).json({
          status: 'error',
          message: 'Todos los campos son obligatorios'
        });
      }
      // Verificar si el username, email o nif_cif ya existen
      const [existing] = await pool.promise().query(
        'SELECT * FROM usuario_basico WHERE username = ? OR email = ? OR nif_cif = ?',
        [username, email, nif_cif]
      );
      if (existing.length > 0) {
        return res.status(409).json({
          status: 'error',
          message: 'Ya existe un usuario básico con ese username, email o NIF/CIF'
        });
      }
      // Verificar el límite de usuarios básicos para el administrador
      const [[adminData]] = await pool.promise().query(
        'SELECT numUsers FROM administrador WHERE id_administrador = ?',
        [req.user.id]
      );
      const [usuariosActuales] = await pool.promise().query(
        'SELECT COUNT(*) AS total FROM usuario_basico WHERE id_administrador = ?',
        [req.user.id]
      );
      if (usuariosActuales[0].total >= adminData.numUsers) {
        return res.status(403).json({
          status: 'error',
          message: 'Has alcanzado el número máximo de usuarios básicos permitidos para este administrador'
        });
      }
      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);
      // Insertar el usuario básico
      const [result] = await pool.promise().query(
        `INSERT INTO usuario_basico (titular, telefono, nif_cif, email, direccion, cp, localidad, provincia, username, password, margen, id_administrador)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [titular, telefono, nif_cif, email, direccion, cp, localidad, provincia, username, hashedPassword, margen, req.user.id]
      );
      res.status(201).json({
        status: 'success',
        message: 'Usuario básico registrado correctamente',
        data: {
          id_usuario_basico: result.insertId,
          titular,
          telefono,
          nif_cif,
          email,
          direccion,
          cp,
          localidad,
          provincia,
          username,
          margen
        }
      });
    } catch (error) {
      console.error('Error al registrar usuario básico:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al registrar usuario básico',
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
        console.log('[LOGIN] Usuario básico encontrado:', usuarioBasico.username);
        const isValidPassword = await bcrypt.compare(password, usuarioBasico.password);
        console.log('[LOGIN] ¿Password válida usuario básico?', isValidPassword);
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

      // Crear token JWT con el id correcto según el rol
      let userId;
      if (role === 'maestro') {
        userId = user.id_maestro;
      } else if (role === 'administrador') {
        userId = user.id_administrador;
      } else if (role === 'usuario_basico') {
        userId = user.id_usuario_basico;
      }
      const token = jwt.sign(
        { 
          id: userId,
          username: user.username,
          role: role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Eliminar la contraseña del objeto de respuesta
      delete user.password;

      // Construir el objeto user con el id correcto según el rol
      let userData = {
        nombre: user.nombre || user.titular,
        apellidos: user.apellidos || '',
        username: user.username,
        email: user.email,
        role: role
      };
      if (role === 'maestro') {
        userData.id = user.id_maestro;
      } else if (role === 'administrador') {
        userData.id = user.id_administrador;
      } else if (role === 'usuario_basico') {
        userData.id = user.id_usuario_basico;
      }

      res.status(200).json({
        status: 'success',
        message: 'Login exitoso',
        data: {
          token,
          user: userData
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
  // Ruta protegida para obtener el perfil según el rol
  app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
      let userProfile = null;
      let query = '';
      let params = [];

      if (req.user.role === 'maestro') {
        query = 'SELECT id_maestro AS id, nombre, apellidos, username, email, "maestro" AS role FROM maestro WHERE id_maestro = ?';
        params = [req.user.id];
      } else if (req.user.role === 'administrador') {
        query = 'SELECT id_administrador AS id, titular AS nombre, "" AS apellidos, username, email, "administrador" AS role FROM administrador WHERE id_administrador = ?';
        params = [req.user.id];
      } else if (req.user.role === 'usuario_basico') {
        query = 'SELECT id_usuario_basico AS id, titular AS nombre, "" AS apellidos, username, email, "usuario_basico" AS role FROM usuario_basico WHERE id_usuario_basico = ?';
        params = [req.user.id];
      } else {
        return res.status(400).json({
          status: 'error',
          message: 'Rol de usuario no reconocido'
        });
      }

      const [users] = await pool.promise().query(query, params);

      if (users.length === 0) {
        return res.status(404).json({
          status: 'error',
          message: 'Usuario no encontrado'
        });
      }

      userProfile = users[0];
      res.status(200).json({
        status: 'success',
        data: userProfile
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
        id_comercializadora 
      } = req.body;

      // Validar campos requeridos
      if (!titular || !telefono || !nif_cif || !email || !direccion || !cp || 
          !localidad || !provincia || !username || !password || !id_comercializadora) {
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
            localidad, provincia, username, password, id_maestro
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            titular, telefono, nif_cif, email, direccion, cp,
            localidad, provincia, username, hashedPassword, req.user.id
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

  // Endpoint para obtener todos los administradores
  app.get('/api/administradores', async (req, res) => {
    try {
      // Solo permitir a usuarios con rol maestro
      if (req.user && req.user.role !== 'maestro') {
        return res.status(403).json({
          status: 'error',
          message: 'No autorizado para ver administradores'
        });
      }
      // Obtener todos los administradores
      const [admins] = await pool.promise().query(
        'SELECT id_administrador, titular, telefono, nif_cif, email, direccion, cp, localidad, numusers, provincia, username FROM administrador'
      );

      // Para cada admin, obtener el número real de usuarios asociados
      const adminIds = admins.map(a => a.id_administrador);
      let usuariosPorAdmin = {};
      if (adminIds.length > 0) {
        const [userCounts] = await pool.promise().query(
          'SELECT id_administrador, COUNT(*) as usuarios_actuales FROM usuario_basico WHERE id_administrador IN (?) GROUP BY id_administrador',
          [adminIds]
        );
        userCounts.forEach(row => {
          usuariosPorAdmin[row.id_administrador] = row.usuarios_actuales;
        });
      }
      // Añadir campo usuarios_actuales a cada admin
      admins.forEach(admin => {
        admin.usuarios_actuales = usuariosPorAdmin[admin.id_administrador] || 0;
      });

      res.json({
        status: 'success',
        data: admins
      });
    } catch (error) {
      console.error('Error al obtener administradores:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al obtener los administradores'
      });
    }
  });

  // Endpoint para obtener usuarios básicos por id de administrador
  app.get('/api/users/:idAdmin', authenticateToken, async (req, res) => {
    try {
      const idAdmin = req.params.idAdmin;
      console.log('[USERS-BY-ADMIN] idAdmin:', idAdmin);
      console.log('[USERS-BY-ADMIN] req.user:', req.user);
      // Solo permitir a usuarios con rol maestro o el propio administrador
      console.log('[REGISTER-USUARIO-BASICO] req.user:', req.user);
      if (!req.user || (req.user.role !== 'maestro' && !(req.user.role === 'administrador' && req.user.id == idAdmin))) {
        console.warn('[USERS-BY-ADMIN] No autorizado', { user: req.user, idAdmin });
        return res.status(403).json({
          status: 'error',
          message: 'No autorizado para ver los usuarios básicos de este administrador'
        });
      }
      const [usuarios] = await pool.promise().query(
        'SELECT id_usuario, titular, telefono, nif_cif, email, direccion, cp, localidad, provincia, username, margen, id_administrador FROM usuario_basico WHERE id_administrador = ?',
        [idAdmin]
      );
      console.log('[USERS-BY-ADMIN] usuarios encontrados:', usuarios);
      res.json({
        status: 'success',
        data: usuarios
      });
    } catch (error) {
      console.error('[USERS-BY-ADMIN] Error al obtener usuarios básicos por administrador:', error);
      if (error && error.stack) {
        console.error('[USERS-BY-ADMIN] Stack:', error.stack);
      }
      res.status(500).json({
        status: 'error',
        message: 'Error al obtener los usuarios básicos de este administrador',
        error: error && error.message ? error.message : error
      });
    }
  });

  // Endpoint para eliminar un administrador (solo rol maestro)
  app.delete('/api/administrador/:id', authenticateToken, async (req, res) => {
    try {
      if (!req.user || req.user.role !== 'maestro') {
        return res.status(403).json({
          status: 'error',
          message: 'No autorizado para eliminar administradores'
        });
      }
      const id = req.params.id;
      // Eliminar administrador y relaciones asociadas (si aplica)
      // Primero eliminar relaciones en administrador_comercializadora
      await pool.promise().query('DELETE FROM administrador_comercializadora WHERE id_administrador = ?', [id]);
      // Eliminar usuarios básicos asociados
      await pool.promise().query('DELETE FROM usuario_basico WHERE id_administrador = ?', [id]);
      // Eliminar tarifas consultoría asociadas
      await pool.promise().query('DELETE FROM tarifa_consultoria WHERE id_administrador = ?', [id]);
      // Finalmente, eliminar el administrador
      const [result] = await pool.promise().query('DELETE FROM administrador WHERE id_administrador = ?', [id]);
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: 'error',
          message: 'Administrador no encontrado'
        });
      }
      res.json({
        status: 'success',
        message: 'Administrador eliminado correctamente'
      });
    } catch (error) {
      console.error('Error al eliminar administrador:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al eliminar el administrador',
        error: error.message
      });
    }
  });

  // Endpoint para obtener los usuarios básicos de un administrador
  app.get('/api/administrador/:id/usuarios-basicos', authenticateToken, async (req, res) => {
    try {
      const idAdmin = req.params.id;
      // Solo el propio admin o un rol superior puede consultar
      if (!req.user || (req.user.role !== 'administrador' && req.user.role !== 'maestro')) {
        return res.status(403).json({
          status: 'error',
          message: 'No autorizado para consultar los usuarios básicos de este administrador'
        });
      }
      // Si es admin, solo puede consultar los suyos
      if (req.user.role === 'administrador' && req.user.id != idAdmin) {
        return res.status(403).json({
          status: 'error',
          message: 'No autorizado para consultar los usuarios de otro administrador'
        });
      }
      const [usuarios] = await pool.promise().query(
        'SELECT * FROM usuario_basico WHERE id_administrador = ?',
        [idAdmin]
      );
      res.json({
        status: 'success',
        data: usuarios
      });
    } catch (error) {
      console.error('Error al obtener usuarios básicos del administrador:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al obtener usuarios básicos del administrador',
        error: error.message
      });
    }
  });

  // Endpoint para editar un usuario básico
  app.put('/api/usuario-basico/:id', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      // Solo admin dueño o maestro puede editar
      const [[usuario]] = await pool.promise().query('SELECT id_administrador FROM usuario_basico WHERE id_usuario = ?', [id]);
      if (!usuario) {
        return res.status(404).json({ status: 'error', message: 'Usuario básico no encontrado' });
      }
      if (
        req.user.role !== 'maestro' &&
        !(req.user.role === 'administrador' && req.user.id == usuario.id_administrador)
      ) {
        return res.status(403).json({ status: 'error', message: 'No autorizado para editar este usuario básico' });
      }
      // Campos editables
      const allowedFields = [
        'titular','telefono','nif_cif','email','direccion','cp','localidad','provincia','username','margen'
      ];
      const updates = {};
      for (const field of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
          updates[field] = req.body[field];
        }
      }
      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ status: 'error', message: 'No hay campos válidos para actualizar' });
      }
      const setClause = Object.keys(updates).map(field => `${field} = ?`).join(', ');
      const values = Object.values(updates);
      values.push(id);
      const [result] = await pool.promise().query(
        `UPDATE usuario_basico SET ${setClause} WHERE id_usuario = ?`,
        values
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ status: 'error', message: 'Usuario básico no encontrado' });
      }
      res.json({ status: 'success', message: 'Usuario básico actualizado correctamente' });
    } catch (error) {
      console.error('Error al editar usuario básico:', error);
      res.status(500).json({ status: 'error', message: 'Error al editar usuario básico', error: error.message });
    }
  });

  // Endpoint para eliminar un usuario básico
  app.delete('/api/usuario-basico/:id', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      // Solo admin dueño o maestro puede eliminar
      const [[usuario]] = await pool.promise().query('SELECT id_administrador FROM usuario_basico WHERE id_usuario = ?', [id]);
      if (!usuario) {
        return res.status(404).json({ status: 'error', message: 'Usuario básico no encontrado' });
      }
      if (
        req.user.role !== 'maestro' &&
        !(req.user.role === 'administrador' && req.user.id == usuario.id_administrador)
      ) {
        return res.status(403).json({ status: 'error', message: 'No autorizado para eliminar este usuario básico' });
      }
      const [result] = await pool.promise().query('DELETE FROM usuario_basico WHERE id_usuario = ?', [id]);
      if (result.affectedRows === 0) {
        return res.status(404).json({ status: 'error', message: 'Usuario básico no encontrado' });
      }
      res.json({ status: 'success', message: 'Usuario básico eliminado correctamente' });
    } catch (error) {
      console.error('Error al eliminar usuario básico:', error);
      res.status(500).json({ status: 'error', message: 'Error al eliminar usuario básico', error: error.message });
    }
  });


  // Endpoint para actualizar un administrador (excepto id y password)
  app.put('/api/administrador/:id', authenticateToken, async (req, res) => {
    try {
      // Solo permitir a usuarios con rol maestro
      if (!req.user || req.user.role !== 'maestro') {
        return res.status(403).json({
          status: 'error',
          message: 'No autorizado para actualizar administradores'
        });
      }
      const id = req.params.id;
      // Campos permitidos para actualizar
      const allowedFields = [
        'titular',
        'telefono',
        'nif_cif',
        'email',
        'direccion',
        'cp',
        'localidad',
        'provincia',
        'username'
      ];
      // Construir el objeto de actualización excluyendo id y password
      const updates = {};
      for (const field of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
          updates[field] = req.body[field];
        }
      }
      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          status: 'error',
          message: 'No hay campos válidos para actualizar'
        });
      }
      // Construir consulta dinámica
      const setClause = Object.keys(updates).map(field => `${field} = ?`).join(', ');
      const values = Object.values(updates);
      values.push(id);
      const [result] = await pool.promise().query(
        `UPDATE administrador SET ${setClause} WHERE id_administrador = ?`,
        values
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: 'error',
          message: 'Administrador no encontrado'
        });
      }
      res.json({
        status: 'success',
        message: 'Administrador actualizado correctamente'
      });
    } catch (error) {
      console.error('Error al actualizar administrador:', error);
      res.status(500).json({
        status: 'error',
        message: 'Error al actualizar el administrador',
        error: error.message
      });
    }
  });

  // Endpoint para obtener administradores con sus usuarios básicos asociado

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
} catch (error) {
  console.error('Error al iniciar el servidor:', error);
  process.exit(1);
}