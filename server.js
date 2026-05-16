require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const admin = require('firebase-admin');

// ════════════════════════════════════════
// ── DATABASE
// ════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        firebase_uid  VARCHAR(128) UNIQUE NOT NULL,
        email         VARCHAR(255) UNIQUE NOT NULL,
        first_name    VARCHAR(100) NOT NULL,
        second_name   VARCHAR(100) NOT NULL,
        third_name    VARCHAR(100) NOT NULL,
        fourth_name   VARCHAR(100) NOT NULL,
        full_name     VARCHAR(400) NOT NULL,
        student_phone VARCHAR(20) UNIQUE NOT NULL,
        parent_phone  VARCHAR(20) NOT NULL,
        national_id   VARCHAR(20),
        stage         VARCHAR(20),
        grade         VARCHAR(10) NOT NULL,
        gender        VARCHAR(10),
        role          VARCHAR(20) DEFAULT 'student',
        status        VARCHAR(20) DEFAULT 'pending',
        id_image_url  TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS chapters (
        id          SERIAL PRIMARY KEY,
        grade       VARCHAR(10) NOT NULL,
        name        VARCHAR(255) NOT NULL,
        description TEXT,
        bunny_id    VARCHAR(255),
        video_url   TEXT,
        file_url    TEXT,
        sort_order  INT DEFAULT 0,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS quizzes (
        id          SERIAL PRIMARY KEY,
        grade       VARCHAR(10) NOT NULL,
        chapter_id  INT REFERENCES chapters(id) ON DELETE SET NULL,
        name        VARCHAR(255) NOT NULL,
        duration    INT DEFAULT 0,
        start_date  TIMESTAMPTZ,
        end_date    TIMESTAMPTZ,
        questions   JSONB NOT NULL DEFAULT '[]',
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS quiz_results (
        id           SERIAL PRIMARY KEY,
        user_id      INT REFERENCES users(id) ON DELETE CASCADE,
        quiz_id      INT REFERENCES quizzes(id) ON DELETE CASCADE,
        quiz_name    VARCHAR(255),
        score        INT NOT NULL,
        total        INT NOT NULL,
        answers      JSONB,
        submitted_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, quiz_id)
      );

      CREATE TABLE IF NOT EXISTS watch_history (
        id         SERIAL PRIMARY KEY,
        user_id    INT REFERENCES users(id) ON DELETE CASCADE,
        chapter_id INT REFERENCES chapters(id) ON DELETE CASCADE,
        watched_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, chapter_id)
      );

      CREATE TABLE IF NOT EXISTS announcements (
        id         SERIAL PRIMARY KEY,
        title      VARCHAR(255) NOT NULL,
        body       TEXT NOT NULL,
        type       VARCHAR(20) DEFAULT 'normal',
        active     BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS schedule (
        id          SERIAL PRIMARY KEY,
        title       VARCHAR(255) NOT NULL,
        description TEXT,
        event_date  TIMESTAMPTZ NOT NULL,
        type        VARCHAR(20) DEFAULT 'lecture',
        grade       VARCHAR(10),
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS subscriptions (
        id          SERIAL PRIMARY KEY,
        user_id     INT REFERENCES users(id) ON DELETE CASCADE,
        plan        VARCHAR(50) NOT NULL,
        amount      DECIMAL(10,2) NOT NULL,
        status      VARCHAR(20) DEFAULT 'pending',
        paid_at     TIMESTAMPTZ,
        expires_at  TIMESTAMPTZ,
        payment_ref VARCHAR(255),
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_users_firebase_uid  ON users(firebase_uid);
      CREATE INDEX IF NOT EXISTS idx_users_student_phone ON users(student_phone);
      CREATE INDEX IF NOT EXISTS idx_chapters_grade      ON chapters(grade);
      CREATE INDEX IF NOT EXISTS idx_quizzes_grade       ON quizzes(grade);
      CREATE INDEX IF NOT EXISTS idx_quiz_results_user   ON quiz_results(user_id);
      CREATE INDEX IF NOT EXISTS idx_watch_history_user  ON watch_history(user_id);
    `);
    console.log('✅ Database tables initialized');
  } catch (err) {
    console.error('❌ DB init error:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

// ════════════════════════════════════════
// ── FIREBASE ADMIN
// ════════════════════════════════════════
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

// ════════════════════════════════════════
// ── MIDDLEWARE
// ════════════════════════════════════════
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'مفيش token' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    const result = await pool.query(
      'SELECT * FROM users WHERE firebase_uid = $1',
      [decoded.uid]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'اليوزر مش موجود في الـ DB' });
    }
    req.user = result.rows[0];
    req.firebaseUid = decoded.uid;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token غلط أو انتهى' });
  }
}

function requireActive(req, res, next) {
  if (req.user?.status !== 'active' && req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'حسابك لسه تحت المراجعة' });
  }
  next();
}

// ════════════════════════════════════════
// ── APP SETUP
// ════════════════════════════════════════
const app = express();
app.use(helmet());

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim());
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
      cb(null, true);
    } else {
      cb(new Error('CORS: Not allowed'));
    }
  },
  credentials: true
}));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'كتير أوي، استنى شوية' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'محاولات كتير، استنى 15 دقيقة' } });

app.use('/api/', limiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/by-phone', authLimiter);
app.use(express.json({ limit: '5mb' }));

// ════════════════════════════════════════
// ── ROUTES: USERS
// ════════════════════════════════════════
const usersRouter = express.Router();

usersRouter.post('/register', async (req, res) => {
  const { firebaseUid, email, firstName, secondName, thirdName, fourthName, studentPhone, parentPhone, stage, grade, gender, nationalId } = req.body;
  if (!firebaseUid || !email || !firstName || !studentPhone || !grade) {
    return res.status(400).json({ error: 'بيانات ناقصة' });
  }
  try {
    await admin.auth().getUser(firebaseUid);
    const fullName = [firstName, secondName, thirdName, fourthName].filter(Boolean).join(' ');
    const result = await pool.query(`
      INSERT INTO users (firebase_uid, email, first_name, second_name, third_name, fourth_name,
        full_name, student_phone, parent_phone, national_id, stage, grade, gender)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING id, full_name, status, role, grade
    `, [firebaseUid, email, firstName, secondName||'', thirdName||'', fourthName||'',
        fullName, studentPhone, parentPhone||'', nationalId||'', stage||'', grade, gender||'']);
    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      const field = err.detail?.includes('student_phone') ? 'رقم الطالب مسجل قبل كده'
                  : err.detail?.includes('email') ? 'الإيميل مسجل قبل كده'
                  : 'البيانات دي موجودة قبل كده';
      return res.status(409).json({ error: field });
    }
    res.status(500).json({ error: 'حصل خطأ في التسجيل' });
  }
});

usersRouter.get('/admin/stats', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE role='student') AS total,
        COUNT(*) FILTER (WHERE role='student' AND status='active') AS active,
        COUNT(*) FILTER (WHERE role='student' AND status='pending') AS pending,
        COUNT(*) FILTER (WHERE role='student' AND status='blocked') AS blocked
      FROM users
    `);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

usersRouter.get('/me', requireAuth, async (req, res) => {
  const u = req.user;
  res.json({ id: u.id, fullName: u.full_name, firstName: u.first_name, email: u.email, grade: u.grade, status: u.status, role: u.role, studentPhone: u.student_phone, createdAt: u.created_at });
});

usersRouter.get('/by-phone/:phone', async (req, res) => {
  try {
    const result = await pool.query('SELECT email FROM users WHERE student_phone = $1', [req.params.phone]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'رقم الطالب مش موجود' });
    res.json({ email: result.rows[0].email });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في البحث' });
  }
});

usersRouter.get('/', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    const { status, grade, search } = req.query;
    let q = 'SELECT id, full_name, email, student_phone, parent_phone, grade, stage, gender, status, role, created_at FROM users WHERE role != $1';
    const params = ['admin'];
    let i = 2;
    if (status) { q += ` AND status = $${i++}`; params.push(status); }
    if (grade)  { q += ` AND grade = $${i++}`;  params.push(grade); }
    if (search) { q += ` AND (full_name ILIKE $${i} OR student_phone ILIKE $${i} OR email ILIKE $${i})`; params.push(`%${search}%`); i++; }
    q += ' ORDER BY created_at DESC';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

usersRouter.patch('/:id/status', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { status } = req.body;
  if (!['active','pending','blocked'].includes(status)) return res.status(400).json({ error: 'status غلط' });
  try {
    await pool.query('UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2', [status, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

usersRouter.delete('/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    const userRow = await pool.query('SELECT firebase_uid FROM users WHERE id = $1', [req.params.id]);
    if (userRow.rows[0]?.firebase_uid) {
      await admin.auth().deleteUser(userRow.rows[0].firebase_uid).catch(() => {});
    }
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use('/api/users', usersRouter);

// ════════════════════════════════════════
// ── ROUTES: CHAPTERS
// ════════════════════════════════════════
const chaptersRouter = express.Router();

chaptersRouter.get('/watched/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT chapter_id FROM watch_history WHERE user_id = $1', [req.user.id]);
    res.json(result.rows.map(r => r.chapter_id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

chaptersRouter.get('/:grade', requireAuth, requireActive, async (req, res) => {
  const { grade } = req.params;
  if (!['g1','g2','g3'].includes(grade)) return res.status(400).json({ error: 'صف غلط' });
  if (req.user.role !== 'admin' && req.user.grade !== grade) return res.status(403).json({ error: 'ممنوع تشوف صف تاني' });
  try {
    const result = await pool.query('SELECT * FROM chapters WHERE grade = $1 ORDER BY sort_order ASC, created_at ASC', [grade]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

chaptersRouter.post('/', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { grade, name, description, bunnyId, videoUrl, fileUrl, sortOrder } = req.body;
  if (!grade || !name) return res.status(400).json({ error: 'الصف والاسم مطلوبين' });
  try {
    const result = await pool.query(
      'INSERT INTO chapters (grade, name, description, bunny_id, video_url, file_url, sort_order) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [grade, name, description||'', bunnyId||'', videoUrl||'', fileUrl||'', sortOrder||0]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

chaptersRouter.put('/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { name, description, bunnyId, videoUrl, fileUrl, sortOrder } = req.body;
  try {
    const result = await pool.query(
      `UPDATE chapters SET name=COALESCE($1,name), description=COALESCE($2,description),
       bunny_id=COALESCE($3,bunny_id), video_url=COALESCE($4,video_url),
       file_url=COALESCE($5,file_url), sort_order=COALESCE($6,sort_order)
       WHERE id=$7 RETURNING *`,
      [name, description, bunnyId, videoUrl, fileUrl, sortOrder, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'مش موجود' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

chaptersRouter.delete('/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    await pool.query('DELETE FROM chapters WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

chaptersRouter.post('/:id/watch', requireAuth, requireActive, async (req, res) => {
  try {
    await pool.query('INSERT INTO watch_history (user_id, chapter_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use('/api/chapters', chaptersRouter);

// ════════════════════════════════════════
// ── ROUTES: QUIZZES
// ════════════════════════════════════════
const quizzesRouter = express.Router();

quizzesRouter.get('/results/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT quiz_id, quiz_name, score, total, submitted_at FROM quiz_results WHERE user_id = $1 ORDER BY submitted_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.get('/admin/all-results', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    const result = await pool.query(`
      SELECT qr.id, u.full_name, u.grade, qr.quiz_name, qr.score, qr.total,
             ROUND(qr.score::numeric/qr.total*100,1) AS percentage, qr.submitted_at
      FROM quiz_results qr JOIN users u ON u.id = qr.user_id
      ORDER BY qr.submitted_at DESC LIMIT 100
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.get('/leaderboard/:grade', requireAuth, requireActive, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.full_name,
             ROUND(AVG(qr.score::numeric / qr.total * 100), 1) AS avg_score,
             COUNT(qr.id) AS quiz_count,
             (u.id = $2) AS is_me
      FROM quiz_results qr JOIN users u ON u.id = qr.user_id
      WHERE u.grade = $1
      GROUP BY u.id, u.full_name
      ORDER BY avg_score DESC LIMIT 20
    `, [req.params.grade, req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.get('/take/:id', requireAuth, requireActive, async (req, res) => {
  try {
    const quizRes = await pool.query('SELECT * FROM quizzes WHERE id = $1', [req.params.id]);
    if (quizRes.rows.length === 0) return res.status(404).json({ error: 'مش موجود' });
    const quiz = quizRes.rows[0];
    const now = new Date();
    if (quiz.start_date && now < new Date(quiz.start_date)) return res.status(403).json({ error: 'الامتحان لسه ماتبدأش' });
    if (quiz.end_date   && now > new Date(quiz.end_date))   return res.status(403).json({ error: 'انتهى وقت الامتحان' });
    const submitted = await pool.query('SELECT id FROM quiz_results WHERE user_id=$1 AND quiz_id=$2', [req.user.id, req.params.id]);
    if (submitted.rows.length > 0) return res.status(409).json({ error: 'سلمت الامتحان ده قبل كده' });
    const questions = quiz.questions.map(q => ({ question: q.question, options: q.options }));
    res.json({ id: quiz.id, name: quiz.name, duration: quiz.duration, endDate: quiz.end_date, questions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.get('/:id/review', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM quiz_results WHERE quiz_id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'مش سلمت الامتحان ده' });
    const quizRes = await pool.query('SELECT questions, name FROM quizzes WHERE id = $1', [req.params.id]);
    const quiz = quizRes.rows[0];
    const myResult = result.rows[0];
    const reviewed = quiz.questions.map((q, i) => ({
      question: q.question, options: q.options,
      correctAnswer: q.correct_answer, myAnswer: myResult.answers?.[i] ?? null
    }));
    res.json({ quizName: quiz.name, score: myResult.score, total: myResult.total, percentage: Math.round(myResult.score/myResult.total*100), submittedAt: myResult.submitted_at, questions: reviewed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.get('/:grade', requireAuth, requireActive, async (req, res) => {
  const { grade } = req.params;
  if (req.user.role !== 'admin' && req.user.grade !== grade) return res.status(403).json({ error: 'ممنوع' });
  try {
    const result = await pool.query(
      `SELECT id, grade, chapter_id, name, duration, start_date, end_date,
              jsonb_array_length(questions) AS question_count, created_at
       FROM quizzes WHERE grade = $1 ORDER BY created_at DESC`, [grade]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.post('/:id/submit', requireAuth, requireActive, async (req, res) => {
  const { answers } = req.body;
  try {
    const quizRes = await pool.query('SELECT * FROM quizzes WHERE id = $1', [req.params.id]);
    if (quizRes.rows.length === 0) return res.status(404).json({ error: 'مش موجود' });
    const quiz = quizRes.rows[0];
    if (quiz.end_date && new Date() > new Date(quiz.end_date)) return res.status(403).json({ error: 'انتهى وقت الامتحان' });
    const submitted = await pool.query('SELECT id FROM quiz_results WHERE user_id=$1 AND quiz_id=$2', [req.user.id, req.params.id]);
    if (submitted.rows.length > 0) return res.status(409).json({ error: 'سلمت الامتحان ده قبل كده' });
    let score = 0;
    quiz.questions.forEach((q, i) => {
      if (answers[i] !== undefined && parseInt(answers[i]) === parseInt(q.correct_answer)) score++;
    });
    await pool.query(
      'INSERT INTO quiz_results (user_id, quiz_id, quiz_name, score, total, answers) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.user.id, quiz.id, quiz.name, score, quiz.questions.length, JSON.stringify(answers)]
    );
    res.json({ score, total: quiz.questions.length, percentage: Math.round(score/quiz.questions.length*100) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.post('/', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { grade, chapterId, name, duration, startDate, endDate, questions } = req.body;
  if (!grade || !name || !questions?.length) return res.status(400).json({ error: 'بيانات ناقصة' });
  try {
    const result = await pool.query(
      'INSERT INTO quizzes (grade, chapter_id, name, duration, start_date, end_date, questions) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, name, grade',
      [grade, chapterId||null, name, duration||0, startDate||null, endDate||null, JSON.stringify(questions)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

quizzesRouter.delete('/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    await pool.query('DELETE FROM quizzes WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use('/api/quizzes', quizzesRouter);

// ════════════════════════════════════════
// ── ROUTES: ANNOUNCEMENTS
// ════════════════════════════════════════
const announceRouter = express.Router();

announceRouter.get('/', requireAuth, requireActive, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM announcements WHERE active=TRUE ORDER BY created_at DESC LIMIT 20');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

announceRouter.post('/', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { title, body, type } = req.body;
  if (!title || !body) return res.status(400).json({ error: 'العنوان والمحتوى مطلوبين' });
  try {
    const result = await pool.query('INSERT INTO announcements (title, body, type) VALUES ($1,$2,$3) RETURNING *', [title, body, type||'normal']);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

announceRouter.delete('/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    await pool.query('UPDATE announcements SET active=FALSE WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use('/api/announcements', announceRouter);

// ════════════════════════════════════════
// ── ROUTES: SCHEDULE
// ════════════════════════════════════════
const scheduleRouter = express.Router();

scheduleRouter.get('/', requireAuth, requireActive, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM schedule WHERE (grade=$1 OR grade IS NULL) AND event_date >= NOW()-INTERVAL '1 day' ORDER BY event_date ASC LIMIT 30`,
      [req.user.grade]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

scheduleRouter.post('/', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { title, description, eventDate, type, grade } = req.body;
  if (!title || !eventDate) return res.status(400).json({ error: 'العنوان والتاريخ مطلوبين' });
  try {
    const result = await pool.query(
      'INSERT INTO schedule (title, description, event_date, type, grade) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [title, description||'', eventDate, type||'lecture', grade||null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

scheduleRouter.delete('/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    await pool.query('DELETE FROM schedule WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use('/api/schedule', scheduleRouter);

// ════════════════════════════════════════
// ── ROUTES: SUBSCRIPTIONS
// ════════════════════════════════════════
const subsRouter = express.Router();

subsRouter.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM subscriptions WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

subsRouter.post('/request', requireAuth, async (req, res) => {
  const plans = { monthly: { amount: 150 }, term: { amount: 400 }, yearly: { amount: 700 } };
  const { plan } = req.body;
  if (!plans[plan]) return res.status(400).json({ error: 'نوع الاشتراك غلط' });
  try {
    const result = await pool.query(
      "INSERT INTO subscriptions (user_id, plan, amount, status) VALUES ($1,$2,$3,'pending') RETURNING *",
      [req.user.id, plan, plans[plan].amount]
    );
    res.status(201).json({ subscription: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

subsRouter.patch('/:id/confirm', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const planDurations = { monthly: 30, term: 120, yearly: 365 };
  const { paymentRef } = req.body;
  try {
    const subRes = await pool.query('SELECT * FROM subscriptions WHERE id=$1', [req.params.id]);
    if (subRes.rows.length === 0) return res.status(404).json({ error: 'مش موجود' });
    const sub = subRes.rows[0];
    const expiresAt = new Date(Date.now() + (planDurations[sub.plan]||30) * 24*60*60*1000);
    await pool.query("UPDATE subscriptions SET status='paid', paid_at=NOW(), expires_at=$1, payment_ref=$2 WHERE id=$3", [expiresAt, paymentRef||null, req.params.id]);
    await pool.query("UPDATE users SET status='active' WHERE id=$1", [sub.user_id]);
    res.json({ success: true, expiresAt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

subsRouter.get('/', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    const result = await pool.query(`
      SELECT s.*, u.full_name, u.student_phone, u.grade
      FROM subscriptions s JOIN users u ON u.id=s.user_id
      ORDER BY s.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use('/api/subscriptions', subsRouter);

// ════════════════════════════════════════
// ── EXPORT: STUDENTS JSON
// ════════════════════════════════════════
app.get('/api/export/students', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  try {
    const result = await pool.query(`
      SELECT
        full_name        AS "الاسم الكامل",
        stage            AS "المرحلة",
        grade            AS "الصف",
        parent_phone     AS "رقم ولي الأمر",
        student_phone    AS "رقم الطالب",
        gender           AS "النوع",
        national_id      AS "الرقم القومي",
        TO_CHAR(created_at, 'YYYY-MM-DD') AS "تاريخ التسجيل"
      FROM users
      WHERE role = 'student'
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// ── HEALTH + ERRORS
// ════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.use((req, res) => res.status(404).json({ error: 'المسار ده مش موجود' }));
app.use((err, req, res, next) => { console.error(err.message); res.status(500).json({ error: 'خطأ في السيرفر' }); });

// ════════════════════════════════════════
// ── START
// ════════════════════════════════════════
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Wafa Backend on port ${PORT}`));
}).catch(err => {
  console.error('Failed to init DB:', err.message);
  process.exit(1);
});
