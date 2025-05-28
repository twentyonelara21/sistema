const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const fs = require('fs');
require('dotenv').config();

// Cloudinary
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'tickets',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'xlsx']
  }
});

const upload = multer({ storage });

const app = express();
const port = process.env.PORT || 3000;

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
        category ENUM('Plomería', 'Eléctrico', 'Luces', 'Aires acondicionados', 'Jardinería', 'Traslados', 'Pintura', 'Albañilería', 'Mudanzas', 'Computadora', 'Internet', 'Software', 'Hardware') NOT NULL,
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
  const image = req.file ? req.file.path : null; // URL pública de Cloudinary

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
    await sendTicketCreationEmail(ticketId, department, requester, description);
    res.json({ message: 'Ticket creado', ticketId });
  } catch (error) {
    console.error('Error en /api/tickets:', error);
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

    console.log('Query ejecutada:', query);
    console.log('Parámetros:', params);

    const [tickets] = await pool.query(query, params);
    console.log('Tickets devueltos:', tickets.map(t => ({ id: t.id, user_id: t.user_id, requester: t.requester })));
    res.json(tickets);
  } catch (error) {
    console.error('Error en /api/tickets:', error);
    res.status(500).json({ error: 'Error al listar tickets', details: error.message });
  }
});

// Endpoint: Assign ticket
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
  } catch (error) {
    console.error('Error en /api/tickets/:id/assign:', error);
    res.status(500).json({ error: 'Error al asignar ticket' });
  }
});

// Endpoint: Transfer ticket
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
  } catch (error) {
    console.error('Error en /api/tickets/:id/transfer:', error);
    res.status(500).json({ error: 'Error al transferir ticket' });
  }
});

// Endpoint: Update ticket status
app.put('/api/tickets/:id', upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { status, userId, observations } = req.body;
  const file = req.file ? req.file.path : null; // URL pública de Cloudinary

  if (!status || !userId) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {
    // ... (tu lógica de permisos igual) ...
    await pool.query('UPDATE tickets SET status = ? WHERE id = ?', [status, id]);
    await pool.query(
      'INSERT INTO ticket_status_history (ticket_id, status, changed_at, observations, user_id, attachment) VALUES (?, ?, NOW(), ?, ?, ?)',
      [id, status, observations || '', userId, file]
    );
    res.json({ message: 'Estado actualizado' });
  } catch (error) {
    console.error('Error en /api/tickets/:id:', error);
    res.status(500).json({ error: 'Error al actualizar estado', details: error.message });
  }
});

// Endpoint: Reopen ticket (admin only)
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
  } catch (error) {
    console.error('Error en /api/tickets/:id/reopen:', error);
    res.status(500).json({ error: 'Error al reabrir ticket' });
  }
});

// Endpoint: Get ticket status history
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

    // Permitir acceso si:
    // 1. El usuario es admin
    // 2. El usuario es el creador del ticket (user_id)
    // 3. El usuario es el asignado (assigned_to)
    // 4. El ticket pertenece al departamento del usuario
    if (role !== 'admin' && 
        ticket.user_id !== parseInt(currentUserId) && 
        ticket.assigned_to !== parseInt(currentUserId) && 
        ticket.department !== department) {
      console.log('No autorizado: userId:', userId, 
                  'ticket department:', ticket.department, 
                  'user department:', department, 
                  'ticket user_id:', ticket.user_id, 
                  'ticket assigned_to:', ticket.assigned_to);
      return res.status(403).json({ error: 'No autorizado para ver el historial de otro departamento' });
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
  } catch (error) {
    console.error('Error en /api/tickets/:id/history:', error);
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// Endpoint: Forgot password
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Correo electrónico inválido' });
  }
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'No existe un usuario con ese correo' });
    }
    const user = users[0];
    // Generar nueva contraseña aleatoria
    const newPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);

    // Enviar correo con la nueva contraseña
    const mailOptions = {
      from: process.env.SMTP_FROM,
      to: email,
      subject: 'Restablecimiento de contraseña - Sistema de Tickets',
      text: `Hola ${user.username},\n\nTu nueva contraseña temporal es: ${newPassword}\n\nPor favor, inicia sesión y cámbiala lo antes posible.\n\nSaludos,\nEl equipo de Soporte`
    };
    await transporter.sendMail(mailOptions);

    res.json({ message: 'Correo enviado' });
  } catch (error) {
    console.error('Error en /api/forgot-password:', error);
    res.status(500).json({ error: 'Error al restablecer la contraseña' });
  }
});

app.get('/api/dashboard/tiempo-promedio', async (req, res) => {
  try {
    const [result] = await pool.query(`
      SELECT 
        u.username AS asignado,
        ROUND(AVG(TIMESTAMPDIFF(MINUTE, t.created_at, 
          (SELECT h.changed_at FROM ticket_status_history h WHERE h.ticket_id = t.id AND h.status = 'Resuelto' ORDER BY h.changed_at DESC LIMIT 1)
        )), 2) AS tiempo_promedio_minutos
      FROM tickets t
      JOIN users u ON t.assigned_to = u.id
      WHERE t.status = 'Resuelto'
      GROUP BY u.username
      ORDER BY tiempo_promedio_minutos ASC
    `);
    res.json(result);
  } catch (error) {
    console.error('Error en /api/dashboard/tiempo-promedio:', error);
    res.status(500).json({ error: 'Error al obtener el tiempo promedio' });
  }
});

app.get('/api/dashboard/solicitante-mas-activo', async (req, res) => {
  try {
    const [result] = await pool.query(`
      SELECT requester, COUNT(*) AS total
      FROM tickets
      GROUP BY requester
      ORDER BY total DESC
      LIMIT 1
    `);
    res.json(result[0] || {});
  } catch (error) {
    console.error('Error en /api/dashboard/solicitante-mas-activo:', error);
    res.status(500).json({ error: 'Error al obtener el solicitante más activo' });
  }
});

app.get('/api/dashboard/categorias-por-departamento', async (req, res) => {
  try {
    const [result] = await pool.query(`
      SELECT department, category, COUNT(*) AS total
      FROM tickets
      GROUP BY department, category
      ORDER BY department, total DESC
    `);
    // Agrupa por departamento para facilitar el frontend
    const agrupado = {};
    result.forEach(row => {
      if (!agrupado[row.department]) agrupado[row.department] = [];
      agrupado[row.department].push({ categoria: row.category, total: row.total });
    });
    res.json(agrupado);
  } catch (error) {
    console.error('Error en /api/dashboard/categorias-por-departamento:', error);
    res.status(500).json({ error: 'Error al obtener categorías por departamento' });
  }
});

app.get('/api/dashboard/asignado-mas-activo', async (req, res) => {
  try {
    const [result] = await pool.query(`
      SELECT u.username AS asignado, COUNT(*) AS total
      FROM tickets t
      JOIN users u ON t.assigned_to = u.id
      GROUP BY u.username
      ORDER BY total DESC
      LIMIT 1
    `);
    res.json(result[0] || {});
  } catch (error) {
    console.error('Error en /api/dashboard/asignado-mas-activo:', error);
    res.status(500).json({ error: 'Error al obtener el asignado más activo' });
  }
});

async function cargarDashboard() {
  // Tiempo promedio
  const tiempo = await fetch('/api/dashboard/tiempo-promedio').then(r => r.json());
  // Solicitante más activo
  const solicitante = await fetch('/api/dashboard/solicitante-mas-activo').then(r => r.json());
  // Categorías por departamento
  const categorias = await fetch('/api/dashboard/categorias-por-departamento').then(r => r.json());
  // Asignado más activo
  const asignado = await fetch('/api/dashboard/asignado-mas-activo').then(r => r.json());

  // Aquí puedes renderizar los datos en tu HTML
  console.log({ tiempo, solicitante, categorias, asignado });
}

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Start server
initDb()
  .then(() => {
    app.listen(port, '0.0.0.0', () => {
      console.log(`Servidor corriendo en puerto ${port}`);
    });
  })
  .catch(error => {
    console.error('No se pudo iniciar el servidor:', error);
    process.exit(1);
  });