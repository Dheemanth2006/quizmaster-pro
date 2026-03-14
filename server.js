/**
 * QuizMaster Pro — Production Server
 * ────────────────────────────────────
 * Express + plain JSON file storage (zero native compilation).
 * No better-sqlite3, no native deps — builds on every platform.
 *
 * Environment variables (Railway → Variables tab):
 *   SESSION_SECRET   — any long random string (REQUIRED in prod)
 *   NODE_ENV         — production
 *   PORT             — set automatically by Railway, do NOT add this
 */

'use strict';

const path    = require('path');
const fs      = require('fs');
const express = require('express');
const cors    = require('cors');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const { body, validationResult } = require('express-validator');

const app    = express();
const PORT   = process.env.PORT || 4001;
const isProd = process.env.NODE_ENV === 'production';

/* ─────────────────────────────────────────────────────────────
   JSON FILE DATABASE  (no native deps — works everywhere)
   Data is saved to quizmaster-db.json next to server.js.
   On Railway this file lives in the container filesystem.
───────────────────────────────────────────────────────────── */
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'quizmaster-db.json');

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.error('[db] Read error, starting fresh:', e.message);
  }
  return { teachers: [], students: [] };
}

function saveDB(dbData) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(dbData, null, 2), 'utf8');
  } catch (e) {
    console.error('[db] Write error:', e.message);
  }
}

// Boot: load data and seed demo teacher
let data = loadDB();
if (!data.teachers.find(t => t.email === 'teacher@school.edu')) {
  data.teachers.push({
    id:           'teacher-001',
    name:         'Prof. Johnson',
    email:        'teacher@school.edu',
    passwordHash: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // demo1234
    role:         'teacher',
    createdAt:    new Date('2024-01-01').toISOString()
  });
  saveDB(data);
  console.log('[db] Demo teacher seeded → teacher@school.edu / demo1234');
}

function newId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 6)}`;
}

/* ─────────────────────────────────────────────────────────────
   CORS — allow same-origin + any Railway/Render domain in prod
───────────────────────────────────────────────────────────── */
app.use(cors({
  origin(origin, cb) {
    // No origin = same-origin request (curl, mobile, etc.) — always allow
    if (!origin) return cb(null, true);
    // Local dev origins
    const local = ['http://localhost:4001','http://localhost:5500','http://localhost:3000'];
    if (local.includes(origin)) return cb(null, true);
    // In production allow everything (Railway serves frontend + backend on same domain)
    if (isProd) return cb(null, true);
    cb(new Error('CORS: ' + origin));
  },
  credentials: true
}));

/* ─────────────────────────────────────────────────────────────
   CORE MIDDLEWARE
───────────────────────────────────────────────────────────── */
app.use(express.json());

app.use(session({
  secret:            process.env.SESSION_SECRET || 'quizmaster-dev-secret-CHANGE-IN-PROD',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge:   1000 * 60 * 60 * 8  // 8 hours
  }
}));

// Serve the QuizMaster Pro frontend
// Support both layouts: files in /public subfolder OR at root level
const publicDir = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
  ? path.join(__dirname, 'public')
  : __dirname;
app.use(express.static(publicDir));

/* ─────────────────────────────────────────────────────────────
   AUTH MIDDLEWARE
───────────────────────────────────────────────────────────── */
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

/* ─────────────────────────────────────────────────────────────
   VALIDATION RULES
───────────────────────────────────────────────────────────── */
const registerRules = [
  body('name').trim().notEmpty().isLength({ min: 2, max: 80 })
    .withMessage('Name must be 2–80 characters'),
  body('email').trim().normalizeEmail().isEmail()
    .withMessage('Valid email required'),
  body('password').isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/\d/).withMessage('Password must contain at least one number'),
  body('confirmPassword').custom((v, { req }) => {
    if (v !== req.body.password) throw new Error('Passwords do not match');
    return true;
  })
];

const loginRules = [
  body('email').trim().normalizeEmail().isEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password required')
];

function checkValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(422).json({
      error: 'Validation failed',
      fields: errors.array().reduce((acc, e) => { acc[e.path] = e.msg; return acc; }, {})
    });
    return false;
  }
  return true;
}

/* ═══════════════════════════════════════════════════════════
   POST /api/auth/register/teacher
═══════════════════════════════════════════════════════════ */
app.post('/api/auth/register/teacher', registerRules, async (req, res) => {
  if (!checkValidation(req, res)) return;
  const { name, email, password } = req.body;

  data = loadDB();
  if (data.teachers.find(t => t.email === email) || data.students.find(s => s.email === email)) {
    return res.status(409).json({ error: 'An account with this email already exists.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const teacher = {
      id: newId('teacher'), name: name.trim(), email,
      passwordHash, role: 'teacher', createdAt: new Date().toISOString()
    };
    data.teachers.push(teacher);
    saveDB(data);

    req.session.user = { id: teacher.id, name: teacher.name, email: teacher.email, role: 'teacher' };
    console.log(`[register] Teacher: ${teacher.name} <${teacher.email}>`);
    res.status(201).json({ ok: true, message: 'Teacher account created.', user: req.session.user });
  } catch (err) {
    console.error('[register/teacher]', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

/* ═══════════════════════════════════════════════════════════
   POST /api/auth/register/student
═══════════════════════════════════════════════════════════ */
app.post('/api/auth/register/student', registerRules, async (req, res) => {
  if (!checkValidation(req, res)) return;
  const { name, email, password } = req.body;

  data = loadDB();
  if (data.teachers.find(t => t.email === email) || data.students.find(s => s.email === email)) {
    return res.status(409).json({ error: 'An account with this email already exists.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const student = {
      id: newId('student'), name: name.trim(), email,
      passwordHash, role: 'student', createdAt: new Date().toISOString()
    };
    data.students.push(student);
    saveDB(data);

    req.session.user = { id: student.id, name: student.name, email: student.email, role: 'student' };
    console.log(`[register] Student: ${student.name} <${student.email}>`);
    res.status(201).json({ ok: true, message: 'Student account created.', user: req.session.user });
  } catch (err) {
    console.error('[register/student]', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

/* ═══════════════════════════════════════════════════════════
   POST /api/auth/login/teacher
═══════════════════════════════════════════════════════════ */
app.post('/api/auth/login/teacher', loginRules, async (req, res) => {
  if (!checkValidation(req, res)) return;
  const { email, password } = req.body;

  data = loadDB();
  const teacher = data.teachers.find(t => t.email === email);
  if (!teacher || !(await bcrypt.compare(password, teacher.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  req.session.user = { id: teacher.id, name: teacher.name, email: teacher.email, role: 'teacher' };
  console.log(`[login] Teacher: ${teacher.name}`);
  res.json({ ok: true, user: req.session.user });
});

/* ═══════════════════════════════════════════════════════════
   POST /api/auth/login/student
═══════════════════════════════════════════════════════════ */
app.post('/api/auth/login/student', loginRules, async (req, res) => {
  if (!checkValidation(req, res)) return;
  const { email, password } = req.body;

  data = loadDB();
  const student = data.students.find(s => s.email === email);
  if (!student || !(await bcrypt.compare(password, student.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  req.session.user = { id: student.id, name: student.name, email: student.email, role: 'student' };
  console.log(`[login] Student: ${student.name}`);
  res.json({ ok: true, user: req.session.user });
});

/* ═══════════════════════════════════════════════════════════
   GET /api/auth/me
═══════════════════════════════════════════════════════════ */
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.session.user });
});

/* ═══════════════════════════════════════════════════════════
   POST /api/auth/logout
═══════════════════════════════════════════════════════════ */
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.json({ ok: true, message: 'Logged out.' });
  });
});

/* ═══════════════════════════════════════════════════════════
   GET /api/users/teachers
═══════════════════════════════════════════════════════════ */
app.get('/api/users/teachers', requireAuth, (req, res) => {
  data = loadDB();
  res.json({ teachers: data.teachers.map(({ id, name, email, role, createdAt }) => ({ id, name, email, role, createdAt })) });
});

/* ═══════════════════════════════════════════════════════════
   GET /api/users/students
═══════════════════════════════════════════════════════════ */
app.get('/api/users/students', requireAuth, (req, res) => {
  data = loadDB();
  res.json({ students: data.students.map(({ id, name, email, role, createdAt }) => ({ id, name, email, role, createdAt })) });
});

/* ═══════════════════════════════════════════════════════════
   GET /api/health
═══════════════════════════════════════════════════════════ */
app.get('/api/health', (_req, res) => {
  data = loadDB();
  res.json({
    ok: true, service: 'quizmaster-pro',
    env: process.env.NODE_ENV || 'development',
    teachers: data.teachers.length,
    students:  data.students.length,
    timestamp: new Date().toISOString()
  });
});

/* ═══════════════════════════════════════════════════════════
   IN-MEMORY QUIZ SESSIONS  (shared across all connected clients)
═══════════════════════════════════════════════════════════ */
const sessions = {};

function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c = '';
  for (let i = 0; i < 6; i++) c += chars[Math.floor(Math.random() * chars.length)];
  return sessions[c] ? generateCode() : c;
}

function computeCredibility(flags) {
  const penalize = (n, lo, hi) => Math.min(n, 2) * lo + Math.max(0, n - 2) * hi;
  let s = 100;
  s -= penalize(flags.tabSwitch || 0, 10, 15);
  s -= penalize(flags.copyPaste || 0, 12, 18);
  s -= penalize(flags.inactivity || 0, 7, 10);
  s -= penalize(flags.windowResize || 0, 4, 7);
  return Math.max(0, Math.round(s));
}

/* GET /api/sessions/my — MUST be before /:code routes */
app.get('/api/sessions/my', (req, res) => {
  // Primary: session cookie. Fallback: ?tid= query param (for Railway same-origin cookie edge cases)
  const tid = (req.session && req.session.user)
    ? req.session.user.id
    : (req.query.tid || null);
  console.log(`[sessions/my] tid=${tid}, total sessions=${Object.keys(sessions).length}`);
  const allSessions = Object.values(sessions);
  // If we know the teacher id, filter. Otherwise show all sessions (hackathon mode).
  const filtered = tid
    ? allSessions.filter(s => s.teacherId === tid)
    : allSessions;
  const mySessions = filtered.map(s => ({
    code: s.code, title: s.title, status: s.status,
    studentCount: Object.keys(s.students).length, createdAt: s.createdAt
  }));
  console.log(`[sessions/my] returning ${mySessions.length} sessions`);
  res.json({ ok: true, sessions: mySessions });
});

/* GET /api/sessions/all-students — MUST be before /:code routes */
app.get('/api/sessions/all-students', (req, res) => {
  const all = [];
  Object.values(sessions).forEach(s => {
    Object.values(s.students).forEach(st => {
      const flags = {
        tabSwitch: st.flags.tabSwitch || 0,
        copyPaste: st.flags.copyPaste || 0,
        inactivity: st.flags.inactivity || 0,
        windowResize: st.flags.windowResize || 0
      };
      const totalFlags = Object.values(flags).reduce((a, v) => a + v, 0);
      all.push({
        name: st.name,
        sessionCode: s.code,
        sessionTitle: s.title,
        flags,
        log: st.log || [],
        totalFlags,
        score: st.score,
        total: s.questions.length,
        finished: st.finished,
        credScore: computeCredibility(flags)
      });
    });
  });
  console.log(`[all-students] returning ${all.length} students`);
  res.json({ ok: true, students: all });
});

/* POST /api/sessions/create — teacher publishes a quiz */
app.post('/api/sessions/create', (req, res) => {
  const { quizId, title, questions, teacherId, teacherName } = req.body;
  if (!title || !questions || !questions.length)
    return res.status(400).json({ error: 'Title and questions required.' });
  const tid = (req.session && req.session.user) ? req.session.user.id : (teacherId || 'unknown');
  const tname = (req.session && req.session.user) ? req.session.user.name : (teacherName || 'Teacher');
  const code = generateCode();
  sessions[code] = {
    code, quizId: quizId || null,
    title, questions,
    teacherId: tid,
    teacherName: tname,
    status: 'waiting',
    students: {},
    createdAt: new Date().toISOString()
  };
  console.log(`[session] Created ${code} — "${title}" by ${tname}`);
  res.json({ ok: true, code });
});

/* POST /api/sessions/:code/recreate — teacher gets a new code */
app.post('/api/sessions/:code/recreate', (req, res) => {
  const old = sessions[req.params.code.toUpperCase()];
  if (old) old.status = 'ended';
  const { title, questions, quizId, teacherId, teacherName } = req.body;
  const tid = (req.session && req.session.user) ? req.session.user.id : (teacherId || 'unknown');
  const tname = (req.session && req.session.user) ? req.session.user.name : (teacherName || 'Teacher');
  const code = generateCode();
  sessions[code] = {
    code, quizId: quizId || null,
    title, questions,
    teacherId: tid,
    teacherName: tname,
    status: 'waiting',
    students: {},
    createdAt: new Date().toISOString()
  };
  res.json({ ok: true, code });
});

/* POST /api/sessions/:code/join — student joins */
app.post('/api/sessions/:code/join', (req, res) => {
  const sess = sessions[req.params.code.toUpperCase()];
  if (!sess) return res.status(404).json({ error: 'Room code not found. Check with your teacher.' });
  if (sess.status === 'ended') return res.status(400).json({ error: 'This quiz session has already ended.' });
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Please enter your name.' });
  const sid = 'stu-' + Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 5);
  sess.students[sid] = {
    id: sid, name: name.trim(),
    joinedAt: Date.now(),
    flags: { tabSwitch: 0, windowResize: 0, copyPaste: 0, inactivity: 0 },
    log: [], answers: [], score: 0, finished: false
  };
  if (sess.status === 'waiting') sess.status = 'active';
  console.log(`[session] ${name} joined ${sess.code}`);
  // Send full questions so student can work even if server restarts
  res.json({ ok: true, studentId: sid, sessionCode: sess.code,
    title: sess.title, questionCount: sess.questions.length,
    questions: sess.questions });
});

/* GET /api/sessions/:code/question/:studentId — get next question */
app.get('/api/sessions/:code/question/:studentId', (req, res) => {
  const sess = sessions[req.params.code.toUpperCase()];
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  const student = sess.students[req.params.studentId];
  if (!student) return res.status(404).json({ error: 'Student not found' });
  const qi = student.answers.length;
  if (qi >= sess.questions.length)
    return res.json({ done: true, score: student.score, total: sess.questions.length });
  const q = sess.questions[qi];
  res.json({ done: false, questionIndex: qi, total: sess.questions.length,
    question: { text: q.text, options: q.options, points: q.points || 1, timeSec: q.timeSec || 30 } });
});

/* POST /api/sessions/:code/answer — student submits answer */
app.post('/api/sessions/:code/answer', (req, res) => {
  const sess = sessions[req.params.code.toUpperCase()];
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  const { studentId, answerIndex } = req.body;
  const student = sess.students[studentId];
  if (!student) return res.status(404).json({ error: 'Student not found' });
  const qi = student.answers.length;
  if (qi >= sess.questions.length) return res.json({ done: true, score: student.score });
  const q = sess.questions[qi];
  const correct = answerIndex === q.correctIndex;
  const points = correct ? (q.points || 1) : 0;
  student.answers.push({ answerIndex, correct, points });
  student.score += points;
  const done = student.answers.length >= sess.questions.length;
  if (done) student.finished = true;
  res.json({ ok: true, correct, correctIndex: q.correctIndex, points, done, score: student.score });
});

/* POST /api/sessions/:code/flag — proctoring flag */
app.post('/api/sessions/:code/flag', (req, res) => {
  const sess = sessions[req.params.code.toUpperCase()];
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  const { studentId, type } = req.body;
  const student = sess.students[studentId];
  if (!student) return res.status(404).json({ error: 'Student not found' });
  if (student.flags[type] !== undefined) student.flags[type]++;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  student.log.push({ type, time: ts, question: student.answers.length + 1 });
  const totalFlags = Object.values(student.flags).reduce((a, v) => a + v, 0);
  res.json({ ok: true, flags: student.flags, totalFlags });
});

/* GET /api/sessions/:code/live — teacher polls for live data */
app.get('/api/sessions/:code/live', (req, res) => {
  const sess = sessions[req.params.code.toUpperCase()];
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  const students = Object.values(sess.students).map(s => ({
    id: s.id, name: s.name, score: s.score,
    answered: s.answers.length, total: sess.questions.length,
    flags: s.flags, log: s.log, finished: s.finished,
    credibility: computeCredibility(s.flags)
  }));
  res.json({ ok: true, code: sess.code, title: sess.title, status: sess.status, students });
});

/* GET /api/sessions/my — teacher's active sessions */
/* GET /api/sessions/all-students — all students for credibility tab */
/* (these are now defined BEFORE /:code routes above) */

/* POST /api/sessions/:code/end — end a session */
app.post('/api/sessions/:code/end', (req, res) => {
  const sess = sessions[req.params.code.toUpperCase()];
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  sess.status = 'ended';
  res.json({ ok: true });
});

/* ── SPA Fallback — MUST be last ──────────────────────────── */
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(path.join(publicDir, 'index.html'));
});

/* ── Start ────────────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`\n🚀 QuizMaster Pro running → http://localhost:${PORT}`);
  console.log(`   Env      : ${process.env.NODE_ENV || 'development'}`);
  console.log(`   DB file  : ${DB_PATH}`);
  console.log(`   Demo     : teacher@school.edu / demo1234\n`);
});
