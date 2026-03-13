// server.ts
import "dotenv/config";
import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import Database from "better-sqlite3";
import multer from "multer";
import { GoogleGenAI, Type } from "@google/genai";
import { Parser } from "json2csv";
import ExcelJS from "exceljs";
import Papa from "papaparse";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { validateCSVHeaders } from "./packages/validator/csv.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Build output folder
const distPath = path.join(__dirname, "dist");

// Infra / network
const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

// Secrets
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_for_dev";
const isProd = process.env.NODE_ENV === "production";

// JWT safety: crash in production if fallback is used; warn in dev
if (JWT_SECRET === "fallback_secret_for_dev") {
  if (isProd) {
    console.error(
      "FATAL: JWT_SECRET is using the fallback value in production. Aborting startup."
    );
    process.exit(1);
  } else {
    console.warn(
      "WARNING: JWT_SECRET is using the fallback value (development only). Do NOT use this in production."
    );
  }
}

// Warn if Gemini key missing (optional)
if (!process.env.GEMINI_API_KEY) {
  console.warn("Warning: GEMINI_API_KEY not set — AI endpoints may fail.");
}

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });
const upload = multer({ storage: multer.memoryStorage() });

// Start server
async function startServer() {
  const app = express();

  // Basic middlewares
  app.use(express.json());
  app.use(cookieParser());

  // Database (better-sqlite3)
  const nativeDb = new Database("capmap.db");
  const db = {
    exec: (sql: string) => nativeDb.exec(sql),
    get: (sql: string, ...params: any[]) => nativeDb.prepare(sql).get(...params),
    all: (sql: string, ...params: any[]) => nativeDb.prepare(sql).all(...params),
    run: (sql: string, ...params: any[]) => nativeDb.prepare(sql).run(...params),
  };

  // PRAGMA (sync exec is fine)
  db.exec("PRAGMA journal_mode = WAL");

  // Initialize tables (kept as your schema)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      role TEXT
    );

    CREATE TABLE IF NOT EXISTS it_assets (
      id TEXT PRIMARY KEY,
      name TEXT,
      type TEXT,
      environment TEXT
    );

    CREATE TABLE IF NOT EXISTS capabilities (
      id TEXT PRIMARY KEY,
      name TEXT,
      domain TEXT,
      maturity_level INTEGER,
      owner TEXT,
      linked_system_ids TEXT,
      cost_center TEXT,
      sla_target_ms INTEGER,
      last_reviewed DATETIME
    );

    CREATE TABLE IF NOT EXISTS processes (
      id TEXT PRIMARY KEY,
      name TEXT,
      owner TEXT,
      domain TEXT,
      capability_id TEXT,
      FOREIGN KEY(capability_id) REFERENCES capabilities(id)
    );

    CREATE TABLE IF NOT EXISTS relationships (
      id TEXT PRIMARY KEY,
      source_id TEXT,
      source_type TEXT,
      target_id TEXT,
      target_type TEXT,
      relationship_type TEXT
    );

    CREATE TABLE IF NOT EXISTS metrics (
      id TEXT PRIMARY KEY,
      capability_id TEXT,
      prompt_hash TEXT,
      kpi_json TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(capability_id) REFERENCES capabilities(id)
    );

    CREATE TABLE IF NOT EXISTS visualizations (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      prompt TEXT,
      image_data TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS capability_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      snapshot_date TEXT UNIQUE,
      avg_maturity REAL
    );

    CREATE TABLE IF NOT EXISTS interaction_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      event_type TEXT,
      entity_type TEXT,
      entity_id TEXT,
      metadata_json TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS demo_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      event_type TEXT,
      step INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS generation_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      date TEXT,
      count INTEGER,
      UNIQUE(user_id, date)
    );

    INSERT OR IGNORE INTO capabilities (id, name, domain, maturity_level) VALUES 
    ('cap1', 'Strategic Planning', 'Strategy', 4),
    ('cap2', 'Supply Chain Management', 'Operations', 3),
    ('cap3', 'Customer Relationship Management', 'Sales', 5),
    ('cap4', 'Financial Reporting', 'Finance', 4),
    ('cap5', 'Talent Acquisition', 'HR', 2);
  `);

  // Auth middleware: allow login and non-/api routes (frontend) while protecting /api/*
  const authMiddleware = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    // Allow login endpoint
    if (req.path === "/api/auth/login") return next();
    // Allow non-API routes (frontend assets/pages) to pass without token
    if (!req.path.startsWith("/api/")) return next();

    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      (req as any).user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
  app.use(authMiddleware);

  // --- API routes (kept your original handlers) ---

  app.post("/api/auth/login", async (req, res, next) => {
    try {
      const { email } = req.body;
      let user = db.get("SELECT * FROM users WHERE email = ?", email) as any;
      if (!user) {
        const id = Math.random().toString(36).substring(7);
        const password_hash = await bcrypt.hash("default_password", 10);
        db.run("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)", id, email, password_hash, "user");
        user = { id, email, role: "user" };
      }
      const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "24h" });
      res.cookie("token", token, {
        httpOnly: true,
        secure: isProd,
        sameSite: "lax",
      });
      res.json({ id: user.id, email: user.email, role: user.role });
    } catch (err) {
      next(err);
    }
  });

  app.get("/api/capabilities", async (req, res) => {
    const caps = db.all("SELECT * FROM capabilities");
    res.json(caps);
  });

  app.post("/api/capabilities", async (req, res) => {
    const { name, domain, maturity_level } = req.body;
    const id = Math.random().toString(36).substring(7);
    db.run("INSERT INTO capabilities (id, name, domain, maturity_level) VALUES (?, ?, ?, ?)", id, name, domain, maturity_level);
    res.json({ id, name, domain, maturity_level });
  });

  // (keep all other API endpoints you had — metrics generation, visualizations, demo, export, etc.)
  // For brevity below: paste the same handlers you already have in your repo.
  // --- Metrics Generation ---
  app.post("/api/metrics/generate", async (req, res, next) => {
    try {
      const { capabilityId } = req.body;
      const userId = (req as any).user?.id;
      const today = new Date().toISOString().split("T")[0];
      let usage = db.get("SELECT count FROM generation_usage WHERE user_id = ? AND date = ?", userId, today) as any;
      if (usage && usage.count >= 50) {
        return res.status(429).json({ error: "Daily AI generation limit reached. Please try again after 24 hours." });
      }

      const capability = db.get("SELECT * FROM capabilities WHERE id = ?", capabilityId) as any;
      if (!capability) return res.status(404).json({ error: "Capability not found" });

      let extraContext = "";
      if (capability.cost_center) extraContext += `\nCost Center: ${capability.cost_center}`;
      if (capability.sla_target_ms) extraContext += `\nSLA Target: ${capability.sla_target_ms}ms`;
      if (capability.owner) extraContext += `\nOwner: ${capability.owner}`;

      const prompt = `Generate 8 business metrics for a capability named "${capability.name}" in the "${capability.domain}" domain. ${extraContext}
Include 5 KPIs and 3 Advanced Metrics. 
Return ONLY a JSON array of objects with "name", "value", "unit", and "trend" (up/down/stable).
Constraints: Values must be realistic numbers. Units should be appropriate (%, $, hours, etc.).`;

      const promptHash = crypto.createHash("sha256").update(prompt).digest("hex");

      const cached = db.get(
        "SELECT * FROM metrics WHERE capability_id = ? AND prompt_hash = ? AND timestamp >= datetime('now', '-1 day') ORDER BY timestamp DESC LIMIT 1",
        capabilityId,
        promptHash
      ) as any;
      if (cached) {
        return res.json(JSON.parse(cached.kpi_json));
      }

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                name: { type: Type.STRING },
                value: { type: Type.NUMBER },
                unit: { type: Type.STRING },
                trend: { type: Type.STRING },
              },
              required: ["name", "value", "unit", "trend"],
            },
          },
        },
      });

      const metricsJson = response.text;
      const id = Math.random().toString(36).substring(7);
      db.run("INSERT INTO metrics (id, capability_id, prompt_hash, kpi_json) VALUES (?, ?, ?, ?)", id, capabilityId, promptHash, metricsJson);

      if (usage) {
        db.run("UPDATE generation_usage SET count = count + 1 WHERE user_id = ? AND date = ?", userId, today);
      } else {
        db.run("INSERT INTO generation_usage (user_id, date, count) VALUES (?, ?, 1)", userId, today);
      }

      res.json(JSON.parse(metricsJson));
    } catch (error: any) {
      console.error(error);
      res.status(500).json({ error: "Failed to generate metrics", details: error.message });
    }
  });

  // --- Dashboard / other endpoints (keep your implementations) ---
  app.get("/api/dashboard", async (req, res) => {
    const totalCapabilities = db.get("SELECT COUNT(*) as count FROM capabilities") as any;
    const totalSystems = db.get("SELECT COUNT(*) as count FROM it_assets") as any;
    const avgMaturity = db.get("SELECT AVG(maturity_level) as avg FROM capabilities") as any;

    const today = new Date().toISOString().split("T")[0];
    const userId = (req as any).user?.id || "anonymous";
    db.run(
      "INSERT INTO capability_snapshots (user_id, snapshot_date, avg_maturity) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM capability_snapshots WHERE snapshot_date = ?)",
      userId,
      today,
      avgMaturity.avg || 0,
      today
    );

    const domainDistribution = db.all("SELECT domain as name, COUNT(*) as value FROM capabilities GROUP BY domain");
    const snapshots = db.all("SELECT snapshot_date as name, avg_maturity as value FROM capability_snapshots ORDER BY snapshot_date ASC") as any[];

    res.json({
      metrics: {
        totalCapabilities: totalCapabilities.count,
        totalSystems: totalSystems.count,
        avgMaturity: avgMaturity.avg ? avgMaturity.avg.toFixed(1) : 0,
        criticalGaps: 3,
      },
      charts: {
        domainDistribution: domainDistribution.length ? domainDistribution : [{ name: "None", value: 0 }],
        maturityTrend: [...snapshots, { name: "Current", value: avgMaturity.avg ? parseFloat(avgMaturity.avg.toFixed(1)) : 0 }],
      },
    });
  });

  // (you may continue to re-add the rest of your endpoints exactly as in your repo:
  // visualizations, demo endpoints, file upload, export, etc. — omitted here for brevity
  // because they are unchanged from your copy)

  // Health check (required by render.yaml)
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // --- Static + SPA fallback (IMPORTANT: must come AFTER API routes) ---
  if (isProd) {
    // serve built files from dist in prod
    app.use(express.static(distPath));
    // Use regex fallback to avoid Express 5 path-to-regexp bare '*' error and keep /api/* untouched
    app.get(/^(?!\/api).*/, (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  } else {
    // Dev: mount Vite middleware for HMR
    const vite = await createViteServer({ server: { middlewareMode: true } });
    app.use(vite.middlewares);
  }

  // --- Global error handler (last middleware) ---
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error("Unhandled error:", err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: "Internal Server Error", details: err?.message });
  });

  // Start listening
  const server = app.listen(PORT, HOST, () => {
    console.log(`Server listening on http://${HOST}:${PORT} (NODE_ENV=${process.env.NODE_ENV || "development"})`);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.log("Shutting down...");
    try {
      server.close(() => {
        console.log("HTTP server closed.");
        nativeDb.close();
        process.exit(0);
      });
    } catch (e) {
      console.error("Error during shutdown", e);
      process.exit(1);
    }
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});