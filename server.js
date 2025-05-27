const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
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

// MySQL configuration for cPanel database
const pool = mysql.createPool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // ssl: {
  //   rejectUnauthorized: true // Set to false if self-signed certificates are used
  //   // ca: fs.readFileSync('/path/to/ca-cert.pem') // Provide CA certificate if required
  // }
});

// Middleware
const corsOptions = {
  origin: process.env.FRONTEND_URL || '*',
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
        role ENUM('admin', 'supervisor', 'user') NOT NULL,
        must_change_password BOOLEAN DEFAULT FALSE
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
        'INSERT INTO users (username, password, email, department, role, must_change_password) VALUES (?, ?, ?, ?, ?, ?)',
        ['admin', hashedPassword, 'admin@healthypeopleco.com', 'Sistemas', 'admin', false]
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

// Send password reset email
async function sendPasswordResetEmail(email, username, temporaryPassword) {
  const mailOptions = {
    from: process.env.SMTP_FROM,
    to: email,
    subject: 'Restablecimiento de Contraseña',
    text: `Hola ${username},\n\nHemos recibido una solicitud para restablecer tu contraseña. Usa esta contraseña temporal para iniciar sesión:\n\nContraseña Temporal: ${temporaryPassword}\n\nPor favor, cambia tu contraseña inmediatamente después de iniciar sesión.\n\nSi no solicitaste este cambio, contacta al soporte.\n\nSaludos,\nEl equipo de Soporte`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo de restablecimiento enviado a:', email);
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
    return [process.env.SMTP_EMAIL];
  } catch (error) {
    console.error(`Error al obtener correos del departamento ${department}:`, error);
    return [process.env.SMTP_EMAIL];
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
    text: `Hola equipo del departamento de ${department},\n\nSe ha creado una nueva solicitud de ticket con los siguientes detalles:\n\n- ID del Ticket: ${ticketId}\n- Solicitante: ${requester}\n- Descripción: ${description}\n\nPor favor, revisa y asigna el ticket lo antes posible.\n\nSaludos,\nEl Equipo de Soporte`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo enviado a:', departmentEmails.join(','));
  } catch (error) {
    console.error('Error al enviar correo al departamento:', error);
  }
}

// Send status update email
async function sendStatusUpdateEmail(ticketId, requester, newStatus, observations, requesterEmail) {
  const mailOptions = {
    from: process.env.SMTP_FROM,
    to: requesterEmail,
    subject: `Actualización del Ticket #${ticketId}`,
    text: `Hola ${requester},\n\nEl estado de tu ticket #${ticketId} ha sido actualizado:\n\n- Nuevo Estado: ${newStatus}\n- Observaciones: ${observations || 'Sin observaciones'}\n\nSi necesitas más información, contacta al soporte.\n\nSaludos,\nEl Equipo de Soporte`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Correo enviado a:', requesterEmail);
  } catch (error) {
    console.error('Error al enviar correo a:', error);
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
    res.json({
      id: user.id,
      username: user.username,
      department: user.department,
      role: user.role,
      mustChangePassword: user.must_change_password
    });
  } catch (err) {
    console.error('Error en /api/login:', err);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint: Forgot Password
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  console.log('Solicitud de restablecimiento de contraseña para:', email);
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      console.log('Correo no encontrado:', email);
      return res.status(404).json({ error: 'Correo no registrado' });
    }
    const user = users[0];

    // Generate temporary password
    const temporaryPassword = crypto.randomBytes(4).toString('hex'); // 8-character random string
    const hashedPassword = await bcrypt.hash(temporaryPassword, 10);

    // Update user with temporary password and set must_change_password
    await pool.query(
      'UPDATE users SET password = ?, must_change_password = ? WHERE email = ?',
      [hashedPassword, true, email]
    );

    // Send email with temporary password
    await sendPasswordResetEmail(email, user.username, temporaryPassword);

    console.log('Contraseña temporal enviada a:', email);
    res.json({ message: 'Contraseña temporal enviada a tu correo' });
  } catch (err) {
    console.error('Error en /api/forgot-password:', err);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
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
      'INSERT INTO users (username, password, email, department, role, must_change_password) VALUES (?, ?, ?, ?, ?, ?)',
      [username, hashedPassword, email, department, role, false]
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
  } catch (err) {
    console.error('Error en /api/users:', err);
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
  } catch (err) {
    console.error('Error en /api/users/available:', err);
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
    await pool.query('UPDATE users SET password = ?, must_change_password = ? WHERE id = ?', [hashedNewPassword, false, id]);
    console.log('Contraseña cambiada para usuario ID:', id);
    res.json({ message: 'Contraseña cambiada exitosamente' });
  } catch (err) {
    console.error('Error en /api/users/:id/password:', err);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});

// Endpoint: Create ticket
app.post('/api/tickets', upload.single('image'), async (req, res) => {
  const { requester, date, location, category, description, priority, userId, department } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;
  console.log('Datos recibidos:', { requester, date, location, category, description, priority, userId, department, image: !!req.file });

  if (!requester || !userId || !date || !location || !category || !description || !priority || !department) {
    return res.status(400).json({ error: 'Todos los campos obligatorios deben estar completos' });
  }

  try {
    const [result] = await pool.query(
      `INSERT INTO tickets (requester, date, location, category, description, priority, status, department, created_at, image, user_id, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)`,
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

// Endpoint: List tickets (with filters)
app.get('/api/tickets', async (req, res) => {
  const { userId, status, ticketId, requester, category: filterCategory, createdByUser } = req.query;
  console.log('Listando tickets, userId:', userId, 'filtros:', { status, ticketId, requester, filterCategory, createdByUser });

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
    } else if (role !== 'admin') {
      query += ' AND t.department = ?';
      params.push(department);
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

    query += ' ORDER BY t.created_at DESC';
    const [tickets] = await pool.query(query, params);
    console.log('Tickets encontrados:', tickets.length);
    res.json(tickets);
  } catch (err) {
    console.error('Error en /api/tickets:', err);
    res.status(500).json({ error: 'Error al listar tickets' });
  }
});

// Endpoint: Update ticket status
app.put('/api/tickets/:id', upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { status, userId, observations } = req.body;
  const file = req.file ? `/uploads/${req.file.filename}` : null;
  console.log('Actualizando ticket ID:', id, 'datos:', { status, userId, observations, file: !!req.file });

  try {
    const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }

    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('Ticket no encontrado:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];

    const [requester] = await pool.query('SELECT email FROM users WHERE username = ?', [ticket.requester]);
    const requesterEmail = requester.length > 0 && requester[0].email ? requester[0].email : process.env.SMTP_EMAIL;

    await pool.query(
      'UPDATE tickets SET status = ? WHERE id = ?',
      [status, id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, status, observations, userId, file]
    );

    await sendStatusUpdateEmail(id, ticket.requester, status, observations, requesterEmail);
    console.log('Ticket actualizado, ID:', id);
    res.json({ message: 'Estado del ticket actualizado' });
  } catch (err) {
    console.error('Error en /api/tickets/:id:', err);
    res.status(500).json({ error: 'Error al actualizar el ticket' });
  }
});

// Endpoint: Assign ticket
app.put('/api/tickets/:id/assign', async (req, res) => {
  const { id } = req.params;
  const { userId, assignedTo } = req.body;
  console.log('Asignando ticket ID:', id, 'a usuario:', assignedTo);

  try {
    const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }

    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('Ticket no encontrado:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }

    await pool.query(
      'UPDATE tickets SET assigned_to = ? WHERE id = ?',
      [assignedTo, id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, tickets[0].status, `Asignado a usuario ID ${assignedTo}`, userId, null]
    );

    console.log('Ticket asignado, ID:', id);
    res.json({ message: 'Ticket asignado' });
  } catch (err) {
    console.error('Error en /api/tickets/:id/assign:', err);
    res.status(500).json({ error: 'Error al asignar ticket' });
  }
});

// Endpoint: Reopen ticket
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

    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('Ticket no encontrado:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }

    await pool.query(
      'UPDATE tickets SET status = ? WHERE id = ?',
      ['Pendiente', id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, 'Pendiente', observations || 'Ticket reabierto', userId, null]
    );

    console.log('Ticket reabierto, ID:', id);
    res.json({ message: 'Ticket reabierto' });
  } catch (err) {
    console.error('Error en /api/tickets/:id/reopen:', err);
    res.status(500).json({ error: 'Error al reabrir ticket' });
  }
});

// Endpoint: Transfer ticket
app.put('/api/tickets/:id/transfer', async (req, res) => {
  const { id } = req.params;
  const { userId, newDepartment, observations } = req.body;
  console.log('Transfiriendo ticket ID:', id, 'a departamento:', newDepartment);

  try {
    const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }

    const [tickets] = await pool.query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (tickets.length === 0) {
      console.log('Ticket no encontrado:', id);
      return res.status(404).json({ error: 'Ticket no encontrado' });
    }
    const ticket = tickets[0];

    await pool.query(
      'UPDATE tickets SET department = ?, assigned_to = NULL WHERE id = ?',
      [newDepartment, id]
    );

    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, ticket.status, observations || `Transferido a ${newDepartment}`, userId, null]
    );

    await sendTicketCreationEmail(id, newDepartment, ticket.requester, ticket.description);
    console.log('Ticket transferido, ID:', id);
    res.json({ message: 'Ticket transferido' });
  } catch (err) {
    console.error('Error en /api/tickets/:id/transfer:', err);
    res.status(500).json({ error: 'Error al transferir ticket' });
  }
});

// Endpoint: Get ticket history
app.get('/api/tickets/:id/history', async (req, res) => {
  const { id } = req.params;
  const { userId } = req.query;
  console.log('Obteniendo historial para ticket ID:', id, 'userId:', userId);

  try {
    const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      console.log('Usuario no encontrado:', userId);
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }

    const [history] = await pool.query(
      `SELECT h.id, h.ticket_id, h.status, DATE_FORMAT(h.changed_at, '%d/%m/%Y %H:%i:%s') AS changed_at, h.observations, h.user_id, h.attachment, u.username
       FROM ticket_status_history h
       LEFT JOIN users u ON h.user_id = u.id
       WHERE h.ticket_id = ?
       ORDER BY h.changed_at ASC`,
      [id]
    );

    console.log('Historial encontrado para ticket ID:', id, 'entradas:', history.length);
    res.json(history);
  } catch (err) {
    console.error('Error en /api/tickets/:id/history:', err);
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// Start server
app.listen(port, async () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
  try {
    await initDb();
    console.log('Base de datos inicializada correctamente');
  } catch (err) {
    console.error('No se pudo inicializar la base de datos:', err);
    process.exit(1);
  }
});