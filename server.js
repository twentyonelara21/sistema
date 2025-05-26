const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Crear directorio de uploads si no existe
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Configuración de MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ticket_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Configuración de multer para subir archivos
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de archivo no permitido. Solo se permiten imágenes (jpg, png, gif), PDF y Excel (xlsx).'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // Límite de 5MB
});

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'mail.healthypeopleco.com',
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER || 'sistemas@healthypeopleco.com',
    pass: process.env.SMTP_PASS || 'T3cn0l0g14s20'
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Verificar conexión SMTP
transporter.verify((error, success) => {
  if (error) {
    console.log('Error al verificar el transporter:', error);
  } else {
    console.log('Conexión SMTP verificada exitosamente');
  }
});

// Inicializar base de datos
async function initDb() {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('Conexión a la base de datos establecida');

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        department ENUM('Mantenimiento', 'Sistemas') NOT NULL,
        role ENUM('admin', 'supervisor', 'user') NOT NULL
      )
    `);
    console.log('Tabla users verificada/creada');

    await connection.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        requester VARCHAR(50) NOT NULL,
        date DATE NOT NULL,
        location ENUM('Cedis Celaya', 'Cedis Centro', 'Cedis México', 'Cedis León', 'Cedis Tijuana', 'Corporativo', 'Departamentos', 'Labs', 'Estadio') NOT NULL,
        category ENUM('Baños', 'Pintura', 'Electricidad', 'Carpintería', 'Computadora', 'Internet', 'Software', 'Hardware') NOT NULL,
        description TEXT NOT NULL,
        priority ENUM('Baja', 'Media', 'Alta') NOT NULL,
        status ENUM('Pendiente', 'En Proceso', 'Resuelto') NOT NULL,
        department ENUM('Mantenimiento', 'Sistemas') NOT NULL,
        created_at DATETIME NOT NULL,
        image VARCHAR(255),
        user_id INT,
        assigned_to INT,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (assigned_to) REFERENCES users(id)
      )
    `);
    console.log('Tabla tickets verificada/creada');

    await connection.query(`
      CREATE TABLE IF NOT EXISTS ticket_status_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ticket_id INT NOT NULL,
        status ENUM('Pendiente', 'En Proceso', 'Resuelto') NOT NULL,
        changed_at DATETIME NOT NULL,
        observations TEXT,
        user_id INT,
        attachment VARCHAR(255),
        FOREIGN KEY (ticket_id) REFERENCES tickets(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log('Tabla ticket_status_history verificada/creada');

    const [users] = await connection.query('SELECT * FROM users WHERE username = ?', ['admin']);
    if (users.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        'INSERT INTO users (username, password, email, department, role) VALUES (?, ?, ?, ?, ?)',
        ['admin', hashedPassword, 'admin@healthypeopleco.com', 'Sistemas', 'admin']
      );
      console.log('Usuario admin creado: username=admin, password=admin123, email=admin@healthypeopleco.com');
    } else {
      console.log('Usuario admin ya existe');
    }

    const [tickets] = await connection.query('SELECT id, status, created_at, user_id FROM tickets');
    for (const ticket of tickets) {
      const [history] = await connection.query('SELECT * FROM ticket_status_history WHERE ticket_id = ?', [ticket.id]);
      if (history.length === 0) {
        await connection.query(
          'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, ?, ?, ?, ?)',
          [ticket.id, ticket.status, ticket.created_at, 'Estado inicial', ticket.user_id || null, null]
        );
        console.log(`Historial creado para ticket ID ${ticket.id}`);
      }
    }
  } catch (err) {
    console.error('Error al inicializar la base de datos:', err);
    throw err;
  } finally {
    if (connection) connection.release();
  }
}

// Función para enviar correo de bienvenida
async function sendWelcomeEmail(email, username, password) {
  const mailOptions = {
    from: process.env.SMTP_FROM || 'sistemashp@healthypeopleco.com',
    to: email,
    subject: 'Bienvenido al Sistema de Tickets',
    text: `Hola ${username},\n\nBienvenido al Sistema de Tickets. Tus credenciales son:\nUsuario: ${username}\nContraseña: ${password}\n\nPor favor, cambia tu contraseña después de iniciar sesión.\n\nSaludos,\nEl equipo de Soporte`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo de bienvenida enviado a:', email);
  } catch (err) {
    console.error('Error al enviar correo de bienvenida:', err);
    throw err;
  }
}

// Función para obtener los correos de todos los usuarios del departamento
async function getDepartmentEmails(department) {
  try {
    const [users] = await pool.query(
      'SELECT email FROM users WHERE department = ? AND email IS NOT NULL AND email != ""',
      [department]
    );
    if (users.length > 0) {
      const emails = users
        .map(user => user.email)
        .filter(email => email && email.includes('@'));
      if (emails.length > 0) {
        console.log(`Correos encontrados para el departamento ${department}: ${emails.join(', ')}`);
        return emails;
      }
    }
    console.warn(`No se encontraron correos válidos para el departamento ${department}. Usando fallback.`);
    return [process.env.SMTP_FALLBACK || 'soporte@healthypeopleco.com'];
  } catch (err) {
    console.error(`Error al obtener correos del departamento ${department}:`, err);
    return [process.env.SMTP_FALLBACK || 'soporte@healthypeopleco.com'];
  }
}

// Función para enviar correo al departamento cuando se crea un ticket
async function sendTicketCreationEmail(ticketId, department, requester, description) {
  const departmentEmails = await getDepartmentEmails(department);
  if (departmentEmails.length === 0 || !departmentEmails[0] || !departmentEmails[0].includes('@')) {
    console.error('No hay destinatarios válidos, no se enviará el correo:', departmentEmails);
    return;
  }
  const mailOptions = {
    from: process.env.SMTP_FROM || 'sistemashp@healthypeopleco.com',
    to: departmentEmails.join(', '),
    subject: `Nueva Solicitud de Ticket #${ticketId}`,
    text: `Hola equipo del departamento de ${department},\n\nSe ha creado una nueva solicitud de ticket con los siguientes detalles:\n\n- ID del Ticket: ${ticketId}\n- Solicitante: ${requester}\n- Descripción: ${description}\n\nPor favor, revisa y asigna el ticket lo antes posible.\n\nSaludos,\nEl Sistema de Tickets`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo enviado a los destinatarios del departamento:', departmentEmails.join(', '));
  } catch (err) {
    console.error('Error al enviar correo al departamento:', err);
  }
}

// Función para enviar correo al solicitante cuando cambia el estado
async function sendStatusUpdateEmail(ticketId, requester, newStatus, observations, requesterEmail) {
  const mailOptions = {
    from: process.env.SMTP_FROM || 'sistemashp@healthypeopleco.com',
    to: requesterEmail,
    subject: `Actualización del Ticket #${ticketId}`,
    text: `Hola ${requester},\n\nEl estado de tu ticket #${ticketId} ha sido actualizado:\n\n- Nuevo Estado: ${newStatus}\n- Observaciones: ${observations || 'Sin observaciones'}\n\nSi necesitas más información, contacta al soporte.\n\nSaludos,\nEl Sistema de Tickets`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo enviado al solicitante:', requesterEmail);
  } catch (err) {
    console.error('Error al enviar correo al solicitante:', err);
  }
}

// Endpoint: Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Intento de login:', username);
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', username);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    const user = users[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      console.log('Contraseña incorrecta para:', username);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    console.log('Login exitoso:', username);
    res.json({ id: user.id, username: user.username, department: user.department, role: user.role });
  } catch (err) {
    console.error('Error en /api/login:', err);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint: Crear usuario (solo admin)
app.post('/api/users', async (req, res) => {
  const { username, password, email, department, role, adminId } = req.body;
  console.log('Creando usuario:', username);
  try {
    const [admins] = await pool.query('SELECT * FROM users WHERE id = ? AND role = "admin"', [adminId]);
    if (admins.length === 0) {
      console.log('No autorizado para crear usuario, adminId:', adminId);
      return res.status(403).json({ error: 'No autorizado' });
    }
    if (!email || !email.includes('@')) {
      console.log('Correo inválido:', email);
      return res.status(400).json({ error: 'Correo electrónico inválido' });
    }
    const [existingUser] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUser.length > 0) {
      console.log('Nombre de usuario ya existe:', username);
      return res.status(400).json({ error: 'El nombre de usuario ya existe' });
    }
    const [existingEmail] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingEmail.length > 0) {
      console.log('Correo ya registrado:', email);
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password, email, department, role) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, email, department, role]
    );
    try {
      await sendWelcomeEmail(email, username, password);
    } catch (emailErr) {
      console.error('No se pudo enviar el correo, pero el usuario fue creado:', emailErr);
      return res.status(201).json({ message: 'Usuario creado, pero no se pudo enviar el correo de bienvenida' });
    }
    console.log('Usuario creado:', username);
    res.json({ message: 'Usuario creado' });
  } catch (err) {
    console.error('Error en /api/users:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      if (err.sqlMessage.includes('username')) {
        return res.status(400).json({ error: 'El nombre de usuario ya existe' });
      }
      if (err.sqlMessage.includes('email')) {
        return res.status(400).json({ error: 'El correo ya está registrado' });
      }
    }
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

// Endpoint: Listar usuarios (solo admin)
app.get('/api/users', async (req, res) => {
  const { adminId } = req.query;
  console.log('Listando usuarios, adminId:', adminId);
  try {
    const [admins] = await pool.query('SELECT * FROM users WHERE id = ? AND role = "admin"', [adminId]);
    if (admins.length === 0) {
      console.log('No autorizado para listar usuarios, adminId:', adminId);
      return res.status(403).json({ error: 'No autorizado' });
    }
    const [users] = await pool.query('SELECT id, username, email, department, role FROM users');
    console.log('Usuarios listados:', users.length);
    res.json(users);
  } catch (err) {
    console.error('Error en /api/users:', err);
    res.status(500).json({ error: 'Error al listar usuarios' });
  }
});

// Endpoint: Listar usuarios disponibles para asignación
app.get('/api/users/available', async (req, res) => {
  const { userId } = req.query;
  console.log('Listando usuarios disponibles, userId:', userId);
  try {
    const [users] = await pool.query('SELECT department, role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { department, role } = users[0];
    let availableUsers;
    if (role === 'admin') {
      [availableUsers] = await pool.query('SELECT id, username, department FROM users');
    } else {
      [availableUsers] = await pool.query('SELECT id, username, department FROM users WHERE department = ?', [department]);
    }
    console.log('Usuarios disponibles:', availableUsers.length);
    res.json(availableUsers);
  } catch (err) {
    console.error('Error en /api/users/available:', err);
    res.status(500).json({ error: 'Error al listar usuarios disponibles' });
  }
});

// Endpoint: Cambiar contraseña
app.put('/api/users/:id/password', async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword, userId } = req.body;
  console.log('Cambiando contraseña para usuario ID:', id);
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', id);
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    const user = users[0];
    if (parseInt(userId) !== parseInt(id)) {
      console.log('No autorizado para cambiar contraseña, userId:', userId);
      return res.status(403).json({ error: 'No autorizado' });
    }
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) {
      console.log('Contraseña actual incorrecta para usuario ID:', id);
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, id]);
    console.log('Contraseña cambiada para usuario ID:', id);
    res.json({ message: 'Contraseña cambiada exitosamente' });
  } catch (err) {
    console.error('Error en /api/users/:id/password:', err);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});

// Endpoint: Crear ticket
app.post('/api/tickets', upload.single('image'), async (req, res) => {
  const { requester, date, location, category, description, priority, userId, department } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;
  console.log('Datos recibidos:', { requester, date, location, category, description, priority, userId, department, image: req.file });

  if (!requester || !date || !location || !category || !description || !priority || !department) {
    return res.status(400).json({ error: 'Todos los campos obligatorios deben estar completos' });
  }

  try {
    const [result] = await pool.query(
      `INSERT INTO tickets (requester, date, location, category, description, priority, status, department, created_at, image, user_id, assigned_to)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)`,
      [requester, date, location, category, description, priority, 'Pendiente', department, image, userId, null]
    );
    const ticketId = result.insertId;
    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [ticketId, 'Pendiente', 'Estado inicial', userId, null]
    );
    console.log('Ticket creado, ID:', ticketId);

    await sendTicketCreationEmail(ticketId, department, requester, description);
    res.json({ message: 'Ticket creado', ticketId });
  } catch (err) {
    console.error('Error en /api/tickets:', err);
    if (err.message.includes('Tipo de archivo no permitido')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Error al crear ticket', details: err.message });
  }
});

// Endpoint: Listar tickets (con filtros)
app.get('/api/tickets', async (req, res) => {
  const { userId, status, ticketId, requester, category: filterCategory, createdByUser } = req.query;
  console.log('Listando tickets, userId:', userId, 'filters:', { status, ticketId, requester, filterCategory, createdByUser });

  try {
    const [users] = await pool.query('SELECT id, department, role, username FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { id: currentUserId, department, role, username } = users[0];
    let query = `
      SELECT t.id, t.requester, t.date, t.location, t.category, t.description, t.priority, t.status, t.department,
             DATE_FORMAT(t.created_at, '%d/%m/%Y %H:%i:%s') AS created_at, t.image, t.user_id, t.assigned_to,
             u.username AS assigned_username
      FROM tickets t
      LEFT JOIN users u ON t.assigned_to = u.id
      WHERE 1=1
    `;
    const params = [];

    if (createdByUser === 'true') {
      query += ' AND t.user_id = ? AND t.requester = ?';
      params.push(parseInt(currentUserId), username);
      console.log('Filtrando por user_id y requester:', { currentUserId, username });
    } else {
      if (role !== 'admin') {
        query += ' AND t.department = ?';
        params.push(department);
      }
    }

    if (status && status !== 'Todos') {
      query += ' AND t.status = ?';
      params.push(status);
    }
    if (ticketId) {
      query += ' AND t.id = ?';
      params.push(parseInt(ticketId));
    }
    if (requester) {
      query += ' AND t.requester LIKE ?';
      params.push(`%${requester}%`);
    }
    if (filterCategory && filterCategory !== 'Todas') {
      query += ' AND t.category = ?';
      params.push(filterCategory);
    }

    console.log('Query ejecutada:', query);
    console.log('Parámetros:', params);

    const [tickets] = await pool.query(query, params);
    console.log('Tickets devueltos:', tickets.map(t => ({ id: t.id, user_id: t.user_id, requester: t.requester })));
    res.json(tickets);
  } catch (err) {
    console.error('Error en /api/tickets:', err);
    res.status(500).json({ error: 'Error al listar tickets', details: err.message });
  }
});

// Endpoint: Asignar ticket
app.put('/api/tickets/:id/assign', async (req, res) => {
  const { id } = req.params;
  const { userId, assignedTo } = req.body;
  console.log('Asignando ticket ID:', id, 'a userId:', assignedTo);
  try {
    const [users] = await pool.query('SELECT department, role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { department, role } = users[0];
    let tickets;
    if (role === 'admin') {
      [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    } else {
      [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ? AND department = ?', [id, department]);
    }
    if (tickets.length === 0) {
      console.log('Ticket no encontrado o no autorizado, ID:', id);
      return res.status(403).json({ error: 'No autorizado' });
    }
    const ticket = tickets[0];
    if (ticket.status === 'Resuelto' && role !== 'admin') {
      console.log('No se puede asignar un ticket resuelto, ID:', id);
      return res.status(403).json({ error: 'No se puede asignar un ticket resuelto' });
    }
    if (parseInt(assignedTo) === parseInt(userId)) {
      await pool.query('UPDATE tickets SET assigned_to = ? WHERE id = ?', [assignedTo, id]);
      await pool.query(
        'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
        [id, ticket.status, `Ticket autoasignado a usuario ID ${assignedTo}`, userId, null]
      );
      console.log('Ticket autoasignado, ID:', id);
      return res.json({ message: 'Ticket asignado' });
    }
    if (role !== 'admin' && role !== 'supervisor') {
      console.log('No autorizado para asignar a otros, userId:', userId);
      return res.status(403).json({ error: 'Solo admins o supervisores pueden asignar tickets a otros usuarios' });
    }
    if (ticket.assigned_to && ticket.assigned_to !== userId && role !== 'admin') {
      console.log('No autorizado para reasignar, ticket ID:', id);
      return res.status(403).json({ error: 'Solo el usuario asignado o un admin puede reasignar este ticket' });
    }
    await pool.query('UPDATE tickets SET assigned_to = ? WHERE id = ?', [assignedTo, id]);
    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, ticket.status, `Ticket asignado a usuario ID ${assignedTo}`, userId, null]
    );
    console.log('Ticket asignado, ID:', id);
    res.json({ message: 'Ticket asignado' });
  } catch (err) {
    console.error('Error en /api/tickets/:id/assign:', err);
    res.status(500).json({ error: 'Error al asignar ticket' });
  }
});

// Endpoint: Transferir ticket
app.put('/api/tickets/:id/transfer', async (req, res) => {
  const { id } = req.params;
  const { userId, newDepartment, observations } = req.body;
  console.log('Transferiendo ticket ID:', id, 'a departamento:', newDepartment);

  try {
    const [users] = await pool.query('SELECT id, department, role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { department, role } = users[0];
    let tickets;
    if (role === 'admin') {
      [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    } else {
      [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ? AND department = ?', [id, department]);
    }
    if (tickets.length === 0) {
      console.log('Ticket no encontrado o no autorizado, ID:', id);
      return res.status(403).json({ error: 'No autorizado' });
    }
    const ticket = tickets[0];
    if (ticket.status === 'Resuelto' && role !== 'admin') {
      console.log('No se puede transferir un ticket resuelto, ID:', id);
      return res.status(403).json({ error: 'No se puede transferir un ticket resuelto' });
    }
    if (!['Sistemas', 'Mantenimiento'].includes(newDepartment) || newDepartment === ticket.department) {
      console.log('Departamento inválido o igual al actual, newDepartment:', newDepartment);
      return res.status(400).json({ error: 'Selecciona un departamento diferente al actual' });
    }
    await pool.query('UPDATE tickets SET department = ?, assigned_to = NULL WHERE id = ?', [newDepartment, id]);
    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, ticket.status, `Ticket transferido a ${newDepartment}. Observaciones: ${observations}`, userId, null]
    );
    console.log('Ticket transferido, ID:', id, 'a:', newDepartment);
    res.json({ message: 'Ticket transferido' });
  } catch (err) {
    console.error('Error en /api/tickets/:id/transfer:', err);
    res.status(500).json({ error: 'Error al transferir ticket' });
  }
});

// Endpoint: Actualizar estado del ticket
app.put('/api/tickets/:id', upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { status, userId, observations } = req.body;
  const file = req.file ? `/uploads/${req.file.filename}` : null;

  console.log('Actualizando estado ticket ID:', id);
  console.log('Datos recibidos:', { status, userId, observations });
  console.log('Archivo recibido:', req.file);

  if (!status || !userId) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {
    const [users] = await pool.query('SELECT id, department, role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { id: currentUserId, department, role } = users[0];
    let tickets;
    if (role === 'admin') {
      [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    } else {
      [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ? AND department = ?', [id, department]);
    }
    if (tickets.length === 0) {
      console.log('Ticket no encontrado o no autorizado, ID:', id);
      return res.status(403).json({ error: 'No autorizado' });
    }
    const ticket = tickets[0];
    if (ticket.status === 'Resuelto' && role !== 'admin') {
      console.log('No se puede editar un ticket resuelto, ID:', id);
      return res.status(403).json({ error: 'No se puede editar un ticket resuelto' });
    }
    if (ticket.assigned_to !== parseInt(currentUserId) && role !== 'admin') {
      console.log('No autorizado para editar, ticket ID:', id, 'usuario:', currentUserId);
      return res.status(403).json({ error: 'Solo el usuario asignado o un admin puede editar este ticket' });
    }

    const [requesterInfo] = await pool.query('SELECT email FROM users WHERE id = ?', [ticket.user_id]);
    const requesterEmail = requesterInfo.length > 0 && requesterInfo[0].email && requesterInfo[0].email.includes('@') 
      ? requesterInfo[0].email 
      : process.env.SMTP_FALLBACK || 'soporte@healthypeopleco.com';

    await pool.query('UPDATE tickets SET status = ? WHERE id = ?', [status, id]);
    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, status, observations || '', userId, file]
    );
    console.log('Estado actualizado, ticket ID:', id, 'attachment:', file);

    if (ticket.status !== status) {
      await sendStatusUpdateEmail(ticket.id, ticket.requester, status, observations, requesterEmail);
    }

    res.json({ message: 'Estado actualizado' });
  } catch (err) {
    console.error('Error en /api/tickets/:id:', err);
    if (err.message.includes('Tipo de archivo no permitido')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Error al actualizar estado', details: err.message });
  }
});

// Endpoint: Reabrir ticket (solo admin)
app.put('/api/tickets/:id/reopen', async (req, res) => {
  const { id } = req.params;
  const { userId, observations } = req.body;
  console.log('Reabriendo ticket ID:', id);
  try {
    const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { role } = users[0];
    if (role !== 'admin') {
      console.log('No autorizado para reabrir, userId:', userId);
      return res.status(403).json({ error: 'Solo un admin puede reabrir tickets' });
    }
    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('Ticket no encontrado, ID:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];
    if (ticket.status !== 'Resuelto') {
      console.log('El ticket no está resuelto, ID:', id);
      return res.status(400).json({ error: 'El ticket no está en estado Resuelto' });
    }
    await pool.query('UPDATE tickets SET status = ? WHERE id = ?', ['Pendiente', id]);
    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, 'Pendiente', observations || 'Ticket reabierto por admin', userId, null]
    );
    console.log('Ticket reabierto, ID:', id);
    res.json({ message: 'Ticket reabierto' });
  } catch (err) {
    console.error('Error en /api/tickets/:id/reopen:', err);
    res.status(500).json({ error: 'Error al reabrir ticket' });
  }
});

// Endpoint: Obtener historial de estados de un ticket
app.get('/api/tickets/:id/history', async (req, res) => {
  const { id } = req.params;
  const { userId } = req.query;
  console.log('Obteniendo historial para ticket ID:', id, 'userId:', userId);

  try {
    const [users] = await pool.query('SELECT id, department, role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const { id: currentUserId, department, role } = users[0];
    const [tickets] = await pool.query('SELECT user_id, assigned_to, department, status FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('Ticket no encontrado, ID:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];

    if (role === 'admin') {
      console.log('Acceso permitido como admin para ticket ID:', id);
    } else {
      if (ticket.department !== department) {
        console.log('No autorizado: Departamento diferente, userId:', userId, 'ticket department:', ticket.department);
        return res.status(403).json({ error: 'No autorizado para ver el historial de otro departamento' });
      }
      if (ticket.user_id !== parseInt(currentUserId) && ticket.assigned_to !== parseInt(currentUserId)) {
        console.log('Acceso permitido por pertenencia al departamento:', department);
      }
    }

    const [history] = await pool.query(
      `SELECT h.id, h.ticket_id, h.status, 
              DATE_FORMAT(h.changed_at, '%d/%m/%Y %H:%i:%s') AS changed_at, 
              h.observations, h.user_id, h.attachment, u.username
       FROM ticket_status_history h 
       LEFT JOIN users u ON h.user_id = u.id 
       WHERE h.ticket_id = ? 
       ORDER BY h.changed_at DESC`,
      [id]
    );
    console.log('Historial devuelto:', history.map(h => ({ status: h.status, changed_at: h.changed_at, attachment: h.attachment })));
    res.json(history);
  } catch (err) {
    console.error('Error en /api/tickets/:id/history:', err);
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar servidor
initDb()
  .then(() => {
    app.listen(port, '0.0.0.0', () => {
      console.log(`Servidor corriendo en puerto ${port}`);
    });
  })
  .catch(err => {
    console.error('No se pudo iniciar el servidor:', err);
  });