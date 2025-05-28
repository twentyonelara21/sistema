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

// Create uploads directory if it doesn't exist
// WARNING: Render uses an ephemeral filesystem; files in ./uploads will be lost on restart.
// Consider using AWS S3 for persistent storage in production.
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// MySQL configuration for remote cPanel database
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Middleware
const corsOptions = {
  origin: process.env.FRONTEND_URL,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Multer configuration for file uploads
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
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Verify SMTP connection
transporter.verify((error, success) => {
  if (error) {
    console.error('Error al verificar el transporter:', error);
  } else {
    console.log('Conexión SMTP verificada exitosamente');
  }
});

// Function to generate a random password
function generateRandomPassword(length = 10) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
  let password = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset[randomIndex];
  }
  return password;
}

// Initialize database
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
        category ENUM('Baños', 'Pintura', 'Electricidad', 'Carpintería', 'Computador', 'Internet', 'Software', 'Hardware') NOT NULL,
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

// Send welcome email
async function sendWelcomeEmail(email, username, password) {
  const mailOptions = {
    from: process.env.SMTP_FROM,
    to: email,
    subject: 'Bienvenido al Sistema de Tickets',
    text: `Hola ${username},\n\nBienvenido al Sistema de Tickets. Tus credenciales son:\nUsuario: ${username}\nContraseña: ${password}\n\nPor favor, cambia tu contraseña después de iniciar sesión.\n\nSaludos,\nEl equipo de Soporte`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo de bienvenida enviado a:', email);
  } catch (error) {
    console.error('Error al enviar correo de bienvenida:', error);
    throw error;
  }
}

// Send reset password email
async function sendResetPasswordEmail(email, username, newPassword) {
  const mailOptions = {
    from: process.env.SMTP_FROM,
    to: email,
    subject: 'Restablecimiento de Contraseña',
    text: `Hola ${username},\n\nHemos restablecido tu contraseña. Tus nuevas credenciales son:\nUsuario: ${username}\nNueva Contraseña: ${newPassword}\n\nPor favor, inicia sesión y cambia tu contraseña lo antes posible.\n\nSaludos,\nEl equipo de Soporte`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo de restablecimiento de contraseña enviado a:', email);
  } catch (error) {
    console.error('Error al enviar correo de restablecimiento:', error);
    throw error;
  }
}

// Get department emails
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
    return [process.env.SMTP_FALLBACK];
  } catch (error) {
    console.error(`Error al obtener correos del departamento ${department}:`, error);
    return [process.env.SMTP_FALLBACK];
  }
}

// Send ticket creation email
async function sendTicketCreationEmail(ticketId, department, requester, description) {
  const departmentEmails = await getDepartmentEmails(department);
  if (departmentEmails.length === 0 || !departmentEmails[0] || !departmentEmails[0].includes('@')) {
    console.error('No hay destinatarios válidos, no se enviará el correo:', departmentEmails);
    return;
  }
  const mailOptions = {
    from: process.env.SMTP_FROM,
    to: departmentEmails.join(','),
    subject: `Nueva Solicitud de Ticket #${ticketId}`,
    text: `Hola equipo del departamento ${department},\n\nSe ha creado una nueva solicitud de ticket con los siguientes detalles:\n\n- ID del Ticket: ${ticketId}\n- Solicitante: ${requester}\n- Descripción: ${description}\n\nPor favor, revisa y asigna el ticket lo antes posible.\n\nSaludos,\nEl Sistema de Tickets`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo enviado a los destinatarios del departamento:', departmentEmails.join(','));
  } catch (error) {
    console.error('Error al enviar correo al departamento:', error);
  }
}

// Send status update email
async function sendStatusUpdateEmail(ticketId, requester, newStatus, observations, email) {
  const mailOptions = {
    from: process.env.SMTP_FROM,
    to: email,
    subject: `Actualización del Ticket #${ticketId}`,
    text: `Hola ${requester},\n\nEl estado de tu ticket #${ticketId} ha sido actualizado:\n\n- Nuevo Estado: ${newStatus}\n- Observaciones: ${observations || 'Sin observaciones'}\n\nSi necesitas más información, contacta al soporte.\n\nSaludos,\nEl Sistema de Tickets`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo enviado al cliente:', email);
  } catch (error) {
    console.error('Error al enviar correo al cliente:', error);
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
  } catch (error) {
    console.error('Error en /api/login:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint: Reset password
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;
  console.log('Solicitud de restablecimiento de contraseña para:', email);

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      console.log('Correo no encontrado:', email);
      return res.status(404).json({ error: 'Correo no registrado' });
    }
    const user = users[0];
    const newPassword = generateRandomPassword();
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
    console.log('Contraseña restablecida para:', email);

    try {
      await sendResetPasswordEmail(email, user.username, newPassword);
      res.json({ message: 'Contraseña restablecida. Revisa tu correo electrónico.' });
    } catch (emailError) {
      console.error('No se pudo enviar el correo, pero la contraseña fue restablecida:', emailError);
      res.status(201).json({ message: 'Contraseña restablecida, pero no se pudo enviar el correo.' });
    }
  } catch (error) {
    console.error('Error en /api/reset-password:', error);
    res.status(500).json({ error: 'Error al restablecer la contraseña' });
  }
});

// Endpoint: Create user (admin only)
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
    } catch (emailError) {
      console.error('No se pudo enviar el correo, pero el usuario fue creado:', emailError);
      return res.status(201).json({ message: 'Usuario creado, pero no se pudo enviar el correo de bienvenida' });
    }
    console.log('Usuario creado:', username);
    res.json({ message: 'Usuario creado' });
  } catch (error) {
    console.error('Error en /api/users:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      if (error.sqlMessage.includes('username')) {
        return res.status(400).json({ error: 'El nombre de usuario ya existe' });
      }
      if (error.sqlMessage.includes('email')) {
        return res.status(400).json({ error: 'El correo ya está registrado' });
      }
    }
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

// Endpoint: List users (admin only)
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
  } catch (error) {
    console.error('Error en /api/users:', error);
    res.status(500).json({ error: 'Error al listar usuarios' });
  }
});

// Endpoint: List available users for assignment
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
  } catch (error) {
    console.error('Error en /api/users/available:', error);
    res.status(500).json({ error: 'Error al listar usuarios disponibles' });
  }
});

// Endpoint: Change password
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
  } catch (error) {
    console.error('Error en /api/users/:id/password:', error);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});

// Endpoint: Create ticket
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
  } catch (error) {
    console.error('Error en /api/tickets:', error);
    if (error.message.includes('Tipo de archivo no permitido')) {
      return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Error al crear ticket', details: error.message });
  }
});

// Endpoint: List tickets (with filters)
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

    console.log('Ejecutando consulta:', query, params);

    const [tickets] = await pool.query(query, params);
    console.log('Tickets encontrados:', tickets.length);
    res.json(tickets);
  } catch (error) {
    console.error('Error en /api/tickets:', error);
    res.status(500).json({ error: 'Error al listar tickets' });
  }
});

// Endpoint: Update ticket status
app.put('/api/tickets/:id', upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { status, userId, observations } = req.body;
  const file = req.file ? `/uploads/${req.file.filename}` : null;

  console.log('Actualizando estado del ticket ID:', id, { status, userId, observations, file: file ? req.file : null });

  try {
    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('No se encontró el ticket:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];

    const [users] = await pool.query('SELECT id, role, email, username FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const user = users[0];

    if (user.role !== 'admin' && ticket.assigned_to !== parseInt(userId)) {
      console.log('No autorizado para actualizar el ticket:', userId);
      return res.status(403).json({ error: 'No autorizado para actualizar el ticket' });
    }

    await pool.query(
      'UPDATE tickets SET status = ? WHERE id = ?',
      [status, id, id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, status, observations, userId, file]
    );

    if (ticket.user_id) {
      const [ticketUser] = await pool.query('SELECT email, username FROM users WHERE id = ?', [ticket.user_id]);
      if (ticketUser.length > 0 && ticketUser[0].email && ticketUser[0].email.includes('0')) {
        await sendStatusUpdateEmail(id, ticketUser[0].username, status, observations, ticketUser[0].email);
      }
    }

    console.log('Ticket actualizado:', id);
    res.json({ message: 'Estado del ticket actualizado' });
  } catch (error) {
    console.error('Error en /api/tickets/:id:', error);
    res.status(500).json({ error: 'Error al actualizar el estado del ticket' });
  }
});

// Endpoint: Assign ticket
app.put('/api/tickets/:id/assign', async (req, res) => {
  const { id } = req.params;
  const { userId, assignedTo } = req.body;

  console.log('Asignando ticket ID:', id, 'a usuario:', assignedTo);

  try {
    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('No se encontró el ticket:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }

    const [users] = await pool.query('SELECT role, department FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const user = users[0].user;

    const [assignee] = await pool.query('SELECT department FROM users WHERE id = ?', [assignedTo]);
    if (assignee.length === 0) {
      console.log('Usuario asignado no encontrado:', assignedTo);
      return res.status(404).json({ error: 'Usuario asignado no encontrado' });
    }

    if (user.role !== 'admin' && user.role !== 'supervisor' && parseInt(userId) !== parseInt(assignedTo)) {
      console.log('No autorizado para asignar ticket:', userId);
      return res.status(403).json({ error: 'No autorizado para asignar el ticket' });
    }

    await pool.query(
      'UPDATE tickets SET assigned_to = ? WHERE id = ?',
      [assignedTo, id]
    );

    console.log('Ticket ${id} asignado a:', assignedTo);
    res.json({ message: 'Ticket asignado con éxito' });
  } catch (error) {
    console.error('Error en /api/tickets/:id/assign:', error);
    res.status(500).json({ error: 'Error al asignar ticket' });
  }
});

// Endpoint: Reopen ticket
app.put('/api/tickets/:id/reopen', async (req, res) => {
  const { id } = req.params;
  const { userId, observations } = req.body;

  console.log('Reabriendo ticket ID:', id);

  try {
    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('No se encontró el ticket:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];

    const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const user = users[0];

    if (user.role !== 'admin' && ticket.user_id !== parseInt(userId)) {
      console.log('No autorizado para reabrir el ticket:', userId);
      return res.status(403).json({ error: 'No autorizado para reabrir el ticket' });
    }

    await pool.query(
      'UPDATE tickets SET status = ? WHERE id = ?',
      ['Pendiente', id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id) VALUES (?, ?, NOW(), ?, ?)',
      [id, 'Pendiente', observations, userId]
    );

    if (ticket.user_id) {
      const [ticketUser] = await pool.query('SELECT email, username FROM users WHERE id = ?', [ticket.user_id]);
      if (ticketUser.length > 0 && ticketUser[0].email && ticketUser[0].email.includes('0')) {
        await sendStatusUpdateEmail(id, ticketUser[0].username, 'Pendiente', observations, ticketUser[0].email);
      }
    }

    console.log('Ticket reabierto:', id);
    res.json({ message: 'Ticket reabierto con éxito' });
  } catch (error) {
    console.error('Error en /api/tickets/:id/reopen:', error);
    res.status(500).json({ error: 'Error al reabrir el ticket' });
  }
});

// Endpoint: Transfer ticket
app.put('/api/tickets/:id/transfer', async (req, res) => {
  const { id } = req.params;
  const { userId, newDepartment, observations } = req.body;

  console.log('Transfiriendo ticket ID:', id, 'al a departamento:', newDepartment);

  try {
    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('No se encontró el ticket:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];

    const [users] = await pool.query('SELECT role, id FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }
    const user = users[0];

    if (user.role !== 'admin' && ticket.assigned_to !== parseInt(userId)) {
      console.log('No autorizado para transferir el ticket:', userId);
      return res.status(403).json({ error: 'No autorizado para transferir el ticket' });
    }

    await pool.query(
      'UPDATE tickets SET department = ?, assigned_to = null WHERE id = ?',
      [newDepartment, id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id) VALUES (?, ?, NOW(), ?, ?)',
      [id, ticket.status, observations, userId]
    );

    await sendTicketCreationEmail(id, newDepartment, ticket.requester, ticket.description);

    console.log('Ticket transferido a:', id, newDepartment);
    res.json({ message: 'Ticket transferido con éxito' });
  } catch (error) {
    console.error('Error en /api/tickets/:id/transfer:', error);
    res.status(500).json({ error: 'Error al transferir el ticket' });
  }
});

// Endpoint: Get ticket history
app.get('/api/tickets/:id/history', async (req, res) => {
  const { id } = req.params;
  const { userId } = req.query;

  console.log('Solicitando historial para ticket ID:', id, 'userId:', userId);

  try {
    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('No se encontró el ticket:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }

    const [users] = await pool.query('SELECT id, role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }

    const [history] = await pool.query(
      `SELECT tsh.status, DATE_FORMAT(tsh.changed_at, '%d/%m/%Y %H:%i:%s') AS changed_at, tsh.observations, tsh.attachment, u.username
 FROM ticket_status_history tsh
 LEFT JOIN users u ON tsh.user_id = u.id
 WHERE tsh.ticket_id = ?
 ORDER BY tsh.id`,
      [id]
    );

    console.log('Historial encontrado:', history.length, 'entradas');
    res.json(history);
  } catch (error) {
    console.error('Error en /api/tickets/:id/history:', error);
    res.status(500).json({ error: 'Error al cargar el historial del ticket' });
  }
});

// Start server
app.listen(port, async () => {
  try {
    await initDb();
    console.log(`Server running on port ${port}`);
  } catch (err) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
});