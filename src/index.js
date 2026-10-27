import "dotenv/config";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { PrismaClient, Prisma } from "@prisma/client";
import bcrypt from "bcryptjs";
import cors from "cors";
import express from "express";
import { z } from "zod";

const prisma = new PrismaClient();
const app = express();
const port = Number(process.env.PORT ?? 4000);
const origins = new Set((process.env.FRONTEND_ORIGINS ?? "http://localhost:3000").split(",").map((value) => value.trim()).filter(Boolean));
const sessionSecret = process.env.SESSION_SECRET;
const sessionTtlDays = Number(process.env.SESSION_TTL_DAYS ?? 14);
const cookieSameSite = (process.env.COOKIE_SAME_SITE ?? "lax").toLowerCase();
const cookieSecure = process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production" || cookieSameSite === "none";
const cookieName = "arsipin_session";
const oauthCookieName = "arsipin_google_state";

if (!sessionSecret || sessionSecret.length < 32) throw new Error("SESSION_SECRET must contain at least 32 characters.");
if (!Number.isInteger(sessionTtlDays) || sessionTtlDays < 1 || sessionTtlDays > 90) throw new Error("SESSION_TTL_DAYS must be between 1 and 90.");
if (!["lax", "strict", "none"].includes(cookieSameSite)) throw new Error("COOKIE_SAME_SITE must be lax, strict, or none.");

app.disable("x-powered-by");
app.use(cors({
  origin(origin, callback) {
    if (!origin || origins.has(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by CORS."));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));
app.use(express.json({ limit: "256kb" }));

const cookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: cookieSecure,
  sameSite: cookieSameSite,
  path: "/",
  ...(maxAge === undefined ? {} : { maxAge }),
});
const parseCookies = (header = "") => Object.fromEntries(header.split(";").flatMap((part) => {
  const index = part.indexOf("=");
  if (index < 0) return [];
  try { return [[part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())]]; }
  catch { return []; }
}));
const tokenHash = (token) => createHash("sha256").update(token).digest("hex");
const userShape = (user) => ({
  id: user.id,
  name: user.name ?? user.username ?? user.email,
  email: user.email,
  username: user.username,
  role: user.role,
});
const issueSession = async (res, userId) => {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + sessionTtlDays * 24 * 60 * 60 * 1000);
  await prisma.session.create({ data: { tokenHash: tokenHash(token), userId, expiresAt } });
  res.cookie(cookieName, token, cookieOptions(sessionTtlDays * 24 * 60 * 60 * 1000));
};
const getSession = async (req) => {
  const token = parseCookies(req.headers.cookie)[cookieName];
  if (!token) return null;
  const session = await prisma.session.findFirst({
    where: { tokenHash: tokenHash(token), expiresAt: { gt: new Date() } },
    include: { user: true },
  });
  return session?.user ?? null;
};
const requireUser = async (req, res, next) => {
  try {
    req.user = await getSession(req);
    if (!req.user) return res.status(401).json({ message: "Sesi tidak valid. Silakan masuk kembali." });
    return next();
  } catch (error) { return next(error); }
};

const loginSchema = z.object({ identifier: z.string().trim().min(3).max(254), password: z.string().min(8).max(72) });
const registerSchema = z.object({
  username: z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9._-]+$/),
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(72),
  passwordConfirmation: z.string(),
}).refine((data) => data.password === data.passwordConfirmation, { path: ["passwordConfirmation"] });
const documentSchema = z.object({
  judul: z.string().trim().min(3).max(180),
  isi: z.string().trim().min(1).max(200_000),
});
const revisionSchema = documentSchema.extend({ ringkasan: z.string().trim().min(1).max(500) });
const reportValidation = (res) => res.status(400).json({ message: "Periksa input Anda lalu coba lagi." });
const idSchema = z.string().min(1).max(128);
const pageSchema = z.coerce.number().int().min(1).max(1_000_000);
const limitSchema = z.coerce.number().int().min(1).max(100);
const statuses = ["DRAFT", "REVIEW", "APPROVED", "PUBLISHED"];

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.get("/auth/session", async (req, res, next) => {
  try {
    const user = await getSession(req);
    return res.json({ user: user ? userShape(user) : null });
  } catch (error) { return next(error); }
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return reportValidation(res);
    const identifier = parsed.data.identifier.toLowerCase();
    const user = await prisma.user.findFirst({ where: { OR: [{ email: identifier }, { username: identifier }] } });
    if (!user?.passwordHash || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) {
      return res.status(401).json({ message: "Email/username atau password tidak sesuai." });
    }
    await issueSession(res, user.id);
    return res.json({ user: userShape(user) });
  } catch (error) { return next(error); }
});

app.post("/auth/register", async (req, res, next) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: "Periksa username, email, dan password Anda." });
    const username = parsed.data.username.toLowerCase();
    const email = parsed.data.email.toLowerCase();
    const existing = await prisma.user.findFirst({ where: { OR: [{ email }, { username }] } });
    if (existing) return res.status(409).json({ message: "Username atau email sudah digunakan." });
    const user = await prisma.user.create({
      data: { username, email, name: username, passwordHash: await bcrypt.hash(parsed.data.password, 12) },
    });
    await issueSession(res, user.id);
    return res.status(201).json({ id: user.id, username: user.username });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      return res.status(409).json({ message: "Username atau email sudah digunakan." });
    }
    return next(error);
  }
});

app.post("/auth/logout", async (req, res, next) => {
  try {
    const token = parseCookies(req.headers.cookie)[cookieName];
    if (token) await prisma.session.deleteMany({ where: { tokenHash: tokenHash(token) } });
    res.clearCookie(cookieName, cookieOptions());
    return res.status(204).end();
  } catch (error) { return next(error); }
});

const validatedReturnTo = (value) => {
  try {
    const target = new URL(value);
    if (target.username || target.password || target.hash || !origins.has(target.origin)) return null;
    return target;
  } catch { return null; }
};
const equalString = (left, right) => {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};

app.get("/auth/google", (req, res) => {
  const returnTo = validatedReturnTo(req.query.returnTo);
  if (!returnTo) return res.status(400).json({ message: "Alamat returnTo tidak diizinkan." });
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_CALLBACK_URL) {
    return res.status(503).json({ message: "Login Google belum dikonfigurasi." });
  }
  const state = randomBytes(24).toString("base64url");
  res.cookie(oauthCookieName, JSON.stringify({ state, returnTo: returnTo.href }), { ...cookieOptions(10 * 60 * 1000), path: "/auth/google/callback", sameSite: "lax" });
  const authorize = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authorize.search = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_CALLBACK_URL,
    response_type: "code",
    scope: "openid email profile",
    state,
  }).toString();
  return res.redirect(302, authorize);
});

app.get("/auth/google/callback", async (req, res, next) => {
  try {
    let transaction;
    try { transaction = JSON.parse(parseCookies(req.headers.cookie)[oauthCookieName] ?? "null"); } catch { transaction = null; }
    res.clearCookie(oauthCookieName, { ...cookieOptions(), path: "/auth/google/callback", sameSite: "lax" });
    const returnTo = validatedReturnTo(transaction?.returnTo ?? "");
    if (!returnTo || !transaction?.state || !equalString(String(req.query.state ?? ""), transaction.state) || !req.query.code) {
      return res.status(400).json({ message: "Sesi OAuth tidak valid." });
    }
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: String(req.query.code),
        client_id: process.env.GOOGLE_CLIENT_ID ?? "",
        client_secret: process.env.GOOGLE_CLIENT_SECRET ?? "",
        redirect_uri: process.env.GOOGLE_CALLBACK_URL ?? "",
        grant_type: "authorization_code",
      }),
    });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token) throw new Error("Google token exchange failed.");
    const profileResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.email || profile.verified_email !== true) throw new Error("Google account has no verified email.");
    const user = await prisma.user.upsert({
      where: { email: String(profile.email).toLowerCase() },
      update: { name: profile.name ?? null, image: profile.picture ?? null },
      create: { email: String(profile.email).toLowerCase(), name: profile.name ?? null, image: profile.picture ?? null },
    });
    await issueSession(res, user.id);
    return res.redirect(302, returnTo.href);
  } catch (error) { return next(error); }
});

const documentListShape = (document) => ({
  id: document.id,
  judul: document.judul,
  status: document.status,
  createdBy: { name: document.createdBy.name ?? document.createdBy.username ?? document.createdBy.email, username: document.createdBy.username },
  currentVersion: document.currentVersion ? { nomor: document.currentVersion.nomor } : null,
  updatedAt: document.updatedAt.toISOString(),
});

app.get("/documents", requireUser, async (req, res, next) => {
  try {
    const page = pageSchema.safeParse(req.query.page ?? "1");
    const limit = limitSchema.safeParse(req.query.limit ?? "10");
    const status = req.query.status;
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    if (!page.success || !limit.success || (status !== undefined && !statuses.includes(status)) || q.length > 180) return reportValidation(res);
    const where = {
      createdById: req.user.id,
      ...(status ? { status } : {}),
      ...(q ? { judul: { contains: q, mode: "insensitive" } } : {}),
    };
    const [total, documents] = await prisma.$transaction([
      prisma.document.count({ where }),
      prisma.document.findMany({
        where,
        include: { createdBy: { select: { name: true, username: true, email: true } }, currentVersion: { select: { nomor: true } } },
        orderBy: { updatedAt: "desc" },
        skip: (page.data - 1) * limit.data,
        take: limit.data,
      }),
    ]);
    return res.json({ items: documents.map(documentListShape), total, page: page.data, totalPages: Math.max(1, Math.ceil(total / limit.data)) });
  } catch (error) { return next(error); }
});

app.post("/documents", requireUser, async (req, res, next) => {
  try {
    const parsed = documentSchema.safeParse(req.body);
    if (!parsed.success) return reportValidation(res);
    const document = await prisma.$transaction(async (tx) => {
      const created = await tx.document.create({ data: { judul: parsed.data.judul, createdById: req.user.id } });
      const version = await tx.documentVersion.create({
        data: { documentId: created.id, nomor: 1, isi: parsed.data.isi, ringkasan: "Versi awal", createdById: req.user.id },
      });
      return tx.document.update({ where: { id: created.id }, data: { currentVersionId: version.id }, select: { id: true } });
    });
    return res.status(201).json({ id: document.id });
  } catch (error) { return next(error); }
});

app.get("/documents/:id", requireUser, async (req, res, next) => {
  try {
    const id = idSchema.safeParse(req.params.id);
    if (!id.success) return reportValidation(res);
    const document = await prisma.document.findUnique({
      where: { id: id.data },
      include: { createdBy: { select: { name: true, username: true, email: true } }, currentVersion: { select: { nomor: true, isi: true } } },
    });
    if (!document) return res.status(404).json({ message: "Dokumen tidak ditemukan." });
    if (document.createdById !== req.user.id) return res.status(403).json({ message: "Anda tidak memiliki akses ke dokumen ini." });
    return res.json({
      ...documentListShape(document),
      createdById: document.createdById,
      canEdit: document.status === "DRAFT",
      currentVersion: document.currentVersion,
    });
  } catch (error) { return next(error); }
});

app.post("/documents/:id/versions", requireUser, async (req, res, next) => {
  try {
    const id = idSchema.safeParse(req.params.id);
    const parsed = revisionSchema.safeParse(req.body);
    if (!id.success || !parsed.success) return reportValidation(res);
    const outcome = await prisma.$transaction(async (tx) => {
      const document = await tx.document.findUnique({
        where: { id: id.data },
        include: { versions: { orderBy: { nomor: "desc" }, take: 1, select: { nomor: true } } },
      });
      if (!document) return "missing";
      if (document.createdById !== req.user.id) return "forbidden";
      if (document.status !== "DRAFT") return "locked";
      const version = await tx.documentVersion.create({
        data: {
          documentId: document.id,
          nomor: (document.versions[0]?.nomor ?? 0) + 1,
          isi: parsed.data.isi,
          ringkasan: parsed.data.ringkasan,
          createdById: req.user.id,
        },
      });
      await tx.document.update({ where: { id: document.id }, data: { judul: parsed.data.judul, currentVersionId: version.id } });
      return "saved";
    }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable });
    if (outcome === "missing") return res.status(404).json({ message: "Dokumen tidak ditemukan." });
    if (outcome === "forbidden") return res.status(403).json({ message: "Anda tidak memiliki akses ke dokumen ini." });
    if (outcome === "locked") return res.status(409).json({ message: "Dokumen yang tidak berstatus DRAFT tidak dapat direvisi." });
    return res.status(204).end();
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && ["P2002", "P2034"].includes(error.code)) {
      return res.status(409).json({ message: "Revisi bertabrakan dengan perubahan lain. Muat ulang dokumen lalu coba lagi." });
    }
    return next(error);
  }
});

app.use((error, _req, res, _next) => {
  if (error?.message === "Origin is not allowed by CORS.") return res.status(403).json({ message: "Origin tidak diizinkan." });
  if (error instanceof SyntaxError && "body" in error) return res.status(400).json({ message: "Body JSON tidak valid." });
  console.error(error);
  return res.status(500).json({ message: "Terjadi kesalahan pada server." });
});

const server = app.listen(port, () => console.log(`Arsipin API listening on port ${port}`));
const shutdown = async () => {
  server.close(async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
