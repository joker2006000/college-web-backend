const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Initialize AWS S3 Client
const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});



// Configure Multer Storage for file uploads (using memory storage for direct buffer upload to S3)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Create MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    port: process.env.DB_PORT,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log("✅ Database connected successfully!");
        connection.release();
    } catch (err) {
        console.error("❌ Database connection failed:", err);
    }
})();

// JWT Authentication Middleware for Students
function verifyStudentToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

// JWT Authentication Middleware for Admins
function verifyAdminToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ success: false, message: 'Admin access denied. No token provided.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err || !user.isAdmin) return res.status(403).json({ success: false, message: 'Unauthorized admin access.' });
        req.user = user;
        next();
    });
}

/* ==========================================================
   1. AUTHENTICATION API ENDPOINTS (/api/auth)
   ========================================================== */
app.post('/api/auth', upload.single('profilePic'), async (req, res) => {
    const { action, uid, pass, adminId, name, mobile, email } = req.body;

    try {
        // --- STUDENT LOGIN ---
        if (action === 'login') {
            const [rows] = await pool.query('SELECT * FROM Students WHERE uid = ?', [uid]);
            if (rows.length === 0) return res.json({ success: false, message: 'Invalid UID or Password.' });

            const student = rows[0];
            const match = await bcrypt.compare(pass, student.password);
            if (!match) return res.json({ success: false, message: 'Invalid UID or Password.' });

            const token = jwt.sign({ uid: student.uid, name: student.name }, process.env.JWT_SECRET, { expiresIn: '7d' });
            return res.json({ success: true, token, message: 'Login successful' });
        }

        // --- ADMIN LOGIN ---
        if (action === 'admin_login') {
            const [rows] = await pool.query('SELECT * FROM Admins WHERE admin_id = ?', [adminId]);
            if (rows.length === 0 || rows[0].password !== pass) {
                return res.json({ success: false, message: 'Invalid Admin ID or Password.' });
            }

            const token = jwt.sign({ adminId: rows[0].admin_id, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1d' });
            return res.json({ success: true, token, message: 'Admin Login successful' });
        }

        // --- STUDENT REGISTRATION ---
        if (action === 'register') {
            const [existing] = await pool.query('SELECT * FROM Students WHERE uid = ? OR email = ?', [uid, email]);
            if (existing.length > 0) {
                return res.json({ success: false, message: 'UID or Email already registered.' });
            }

            let userpic_url = '';
            if (req.file) {
                const fileName = `profiles/${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(req.file.originalname)}`;
                const uploadParams = {
                    Bucket: process.env.AWS_BUCKET_NAME,
                    Key: fileName,
                    Body: req.file.buffer,
                    ContentType: req.file.mimetype
                };
                await s3Client.send(new PutObjectCommand(uploadParams));
                userpic_url = `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileName}`;
            }

            const hashedPassword = await bcrypt.hash(pass, 10);
            await pool.query(
                'INSERT INTO Students (uid, name, mobile, email, password, userpic_url) VALUES (?, ?, ?, ?, ?, ?)',
                [uid, name, mobile, email, hashedPassword, userpic_url]
            );
            return res.json({ success: true, message: 'Registration successful!' });
        }

        // --- FORGOT PASSWORD ---
        if (action === 'forgot_password') {
            const [rows] = await pool.query('SELECT * FROM Students WHERE uid = ? AND mobile = ?', [uid, mobile]);
            if (rows.length === 0) {
                return res.json({ success: false, message: 'No account found matching this UID and Mobile Number.' });
            }
            return res.json({ success: false, message: 'Please contact HOD to reset your password securely.' });
        }

        res.status(400).json({ success: false, message: 'Invalid action.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error occurred.' });
    }
});

/* ==========================================================
   2. STUDENT PROFILE & PUBLIC EVENTS API
   ========================================================== */

// Get Logged-in Student Profile
app.get('/api/user/profile', verifyStudentToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT uid, name, mobile, email, userpic_url, created_at FROM Students WHERE uid = ?', [req.user.uid]);
        if (rows.length === 0) return res.status(404).json({ success: false, message: 'User not found' });

        const student = rows[0];
        res.json({
            success: true,
            data: {
                name: student.name,
                studentId: student.uid,
                mobile: student.mobile,
                email: student.email,
                picUrl: student.userpic_url
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// Fetch All Events for Public Portal
app.get('/api/events', async (req, res) => {
    try {
        const [events] = await pool.query('SELECT event_id AS id, title, description, closing_date AS closingDate, status, pic_url FROM Events');
        res.json({ success: true, events });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// Event Registration Application Submission (FIXED FOR S3 UPLOAD)
app.post('/api/events/register', upload.single('idCardImage'), async (req, res) => {
    try {
        const { eventId, fullName, mobileNo, email, department, gender, address } = req.body;

        // AWS S3 Upload for ID Card
        let idCardUrl = '';
        if (req.file) {
            const fileName = `ids/${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(req.file.originalname)}`;
            const uploadParams = {
                Bucket: process.env.AWS_BUCKET_NAME,
                Key: fileName,
                Body: req.file.buffer,
                ContentType: req.file.mimetype
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            idCardUrl = `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileName}`;
        }

        let [studentRows] = await pool.query('SELECT uid FROM Students WHERE email = ?', [email]);
        let uid = studentRows.length > 0 ? studentRows[0].uid : null;

        if (!uid) {
            uid = 'GUEST-' + Math.floor(1000 + Math.random() * 9000);
            const dummyHash = await bcrypt.hash('123456', 10);
            await pool.query('INSERT IGNORE INTO Students (uid, name, mobile, email, password) VALUES (?, ?, ?, ?, ?)',
                [uid, fullName, mobileNo, email, dummyHash]);
        }

        await pool.query(
            `INSERT INTO Applications (event_id, uid, department, gender, address, id_card_url) 
             VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE department=?, gender=?, address=?`,
            [eventId, uid, department, gender, address, idCardUrl, department, gender, address]
        );

        res.json({ success: true, message: 'Application submitted successfully!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error submitting application.' });
    }
});

/* ==========================================================
   3. ADMIN MANAGEMENT API ENDPOINTS (/api/admin)
   ========================================================== */

// Admin Home Summary / Dashboard Events
app.get('/api/admin/events', verifyAdminToken, async (req, res) => {
    try {
        const [events] = await pool.query('SELECT event_id AS id, title, description, closing_date AS closingDate, status, pic_url FROM Events');

        const currentEvents = events.filter(e => e.status === 'active');
        const pausedEvents = events.filter(e => e.status === 'paused');

        if (req.query.requested_data === 'home_summary') {
            return res.json({ success: true, data: { currentEvents, pausedEvents } });
        }
        res.json({ success: true, events });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch admin dashboard events' });
    }
});

// Manage Events list view endpoint
app.get('/api/admin/manage-events', verifyAdminToken, async (req, res) => {
    try {
        const [events] = await pool.query('SELECT event_id AS id, title, description, closing_date AS closingDate, status, pic_url FROM Events');
        res.json({ success: true, events });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// Add New Event (FIXED FOR S3 UPLOAD)
app.post('/api/admin/events', verifyAdminToken, upload.single('eventPic'), async (req, res) => {
    try {
        const { title, description, closingDate } = req.body;

        // AWS S3 Upload for Event Picture
        let picUrl = 'placeholder.jpg';
        if (req.file) {
            const fileName = `events/${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(req.file.originalname)}`;
            const uploadParams = {
                Bucket: process.env.AWS_BUCKET_NAME,
                Key: fileName,
                Body: req.file.buffer,
                ContentType: req.file.mimetype
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            picUrl = `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileName}`;
        }

        await pool.query(
            'INSERT INTO Events (title, description, closing_date, pic_url) VALUES (?, ?, ?, ?)',
            [title, description, closingDate, picUrl]
        );

        res.json({ success: true, message: 'Event published successfully!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to add event' });
    }
});

// Toggle Event Status (Active / Paused)
app.patch('/api/admin/events/:id/toggle-status', verifyAdminToken, async (req, res) => {
    try {
        const { status } = req.body;
        await pool.query('UPDATE Events SET status = ? WHERE event_id = ?', [status, req.params.id]);
        res.json({ success: true, message: 'Event status updated successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update status.' });
    }
});

// Delete Event
app.delete('/api/admin/events/:id', verifyAdminToken, async (req, res) => {
    try {
        // 1. Fetch the event to check for an associated S3 image
        const [eventRows] = await pool.query('SELECT pic_url FROM Events WHERE event_id = ?', [req.params.id]);

        if (eventRows.length > 0) {
            const picUrl = eventRows[0].pic_url;

            // 2. Check if the URL points to an actual S3 file (not the placeholder)
            if (picUrl && picUrl !== 'placeholder.jpg' && picUrl.includes('amazonaws.com')) {
                // Extract the file path (key) from the URL by removing the domain part
                const urlObj = new URL(picUrl);
                const fileKey = urlObj.pathname.substring(1); // Removes the leading '/'

                // 3. Delete the object from the S3 bucket
                const deleteParams = {
                    Bucket: process.env.AWS_BUCKET_NAME,
                    Key: fileKey
                };
                await s3Client.send(new DeleteObjectCommand(deleteParams));
            }
        }

        // 4. Delete the event from the MySQL database
        await pool.query('DELETE FROM Events WHERE event_id = ?', [req.params.id]);
        res.json({ success: true, message: 'Event, related applications, and S3 image deleted successfully.' });
    } catch (err) {
        console.error("Error deleting event:", err);
        res.status(500).json({ success: false, message: 'Failed to delete event.' });
    }
});

// Fetch Applications by Event ID and Department
app.get('/api/admin/events/:id/applications', verifyAdminToken, async (req, res) => {
    // FRONTEND TODO:
    // Admin dashboard should call this API
    // Show approve button
    // Show decline button
    // Show decline reason textbox
    // Display student uploaded ID image
    // Display colored status badge
    try {
        const { department } = req.query;
        let query = `
            SELECT 
                a.application_id, s.name, s.uid, s.mobile, s.email, 
                a.gender, a.department, a.address, a.id_card_url,
                a.status, a.decline_reason, a.updated_at, a.reviewed_by,
                e.event_id, e.title
            FROM Applications a 
            JOIN Students s ON a.uid = s.uid 
            JOIN Events e ON a.event_id = e.event_id
            WHERE a.event_id = ?
        `;
        let queryParams = [req.params.id];

        if (department) {
            query += ` AND a.department = ?`;
            queryParams.push(department);
        }

        const [applications] = await pool.query(query, queryParams);
        res.json({ success: true, applications });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to fetch applications.' });
    }
});

/* ==========================================================
   4. NEW APPLICATION TRACKING SYSTEM APIs
   ========================================================== */

// --- STUDENT APIs ---

// Get all applications for the logged-in student
app.get('/api/user/applications', verifyStudentToken, async (req, res) => {
    // FRONTEND TODO:
    // My Applications page
    // Display cards
    // Show uploaded ID image
    // Show status badge
    // Show decline reason
    // Show delete button only if declined
    try {
        const query = `
            SELECT 
                a.application_id, e.event_id, e.title, e.description, e.closing_date, e.pic_url,
                s.uid, s.name, s.email, s.mobile,
                a.department, a.gender, a.address, a.id_card_url, a.applied_on,
                a.status, a.decline_reason, a.updated_at
            FROM Applications a
            JOIN Students s ON a.uid = s.uid
            JOIN Events e ON a.event_id = e.event_id
            WHERE a.uid = ?
            ORDER BY a.applied_on DESC
        `;
        const [applications] = await pool.query(query, [req.user.uid]);
        res.json({ success: true, applications });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to fetch your applications.' });
    }
});

// Delete a declined application
app.delete('/api/user/applications/:applicationId', verifyStudentToken, async (req, res) => {
    try {
        const { applicationId } = req.params;

        // Fetch application to check ownership and status
        const [rows] = await pool.query('SELECT uid, status, id_card_url FROM Applications WHERE application_id = ?', [applicationId]);

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Application not found.' });
        }

        const appRecord = rows[0];

        // Ensure the student owns this application
        if (appRecord.uid !== req.user.uid) {
            return res.status(403).json({ success: false, message: 'Unauthorized to delete this application.' });
        }

        // Ensure application is declined
        if (appRecord.status === 'selected' || appRecord.status === 'under_checking') {
            return res.status(400).json({ success: false, message: 'Only declined applications can be deleted.' });
        }

        // TODO: Future requirement - If AWS S3 cleanup is needed, delete the object using:
        // const fileKey = new URL(appRecord.id_card_url).pathname.substring(1);
        // await s3Client.send(new DeleteObjectCommand({ Bucket: process.env.AWS_BUCKET_NAME, Key: fileKey }));

        // Delete from database
        await pool.query('DELETE FROM Applications WHERE application_id = ?', [applicationId]);
        res.json({ success: true, message: 'Application deleted successfully.' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to delete application.' });
    }
});


// --- ADMIN APIs ---

// Update application status
app.patch('/api/admin/applications/:applicationId/status', verifyAdminToken, async (req, res) => {
    // FRONTEND TODO:
    // Admin dashboard should call this API
    // Show approve button
    // Show decline button
    // Show decline reason textbox
    // Display student uploaded ID image
    // Display colored status badge
    try {
        const { applicationId } = req.params;
        let { status, decline_reason } = req.body;

        const validStatuses = ['under_checking', 'selected', 'declined'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ success: false, message: 'Invalid status provided.' });
        }

        // Handle auto-nulling and required reasons based on status
        if (status === 'selected') {
            decline_reason = null;
        } else if (status === 'declined') {
            if (!decline_reason || decline_reason.trim() === '') {
                return res.status(400).json({ success: false, message: 'Decline reason is required.' });
            }
        } else if (status === 'under_checking') {
            decline_reason = null;
        }

        const adminId = req.user.adminId; // Extracted from verifyAdminToken middleware

        const [updateResult] = await pool.query(
            'UPDATE Applications SET status = ?, decline_reason = ?, reviewed_by = ? WHERE application_id = ?',
            [status, decline_reason, adminId, applicationId]
        );

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Application not found.' });
        }

        // Fetch and return the updated application
        const [updatedRows] = await pool.query('SELECT * FROM Applications WHERE application_id = ?', [applicationId]);

        res.json({
            success: true,
            message: 'Application status updated successfully.',
            application: updatedRows[0]
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to update application status.' });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running smoothly on http://localhost:${PORT}`);
});