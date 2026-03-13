import "dotenv/config";
import express from "express";
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

// Vite builds the frontend into dist/ relative to repo root
const distPath = path.join(__dirname, "dist");

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_for_dev";

// Fixed JWT_SECRET guard: only fatal-exit in production
if (JWT_SECRET === "fallback_secret_for_dev") {
  if (process.env.NODE_ENV === "production") {
    console.error("FATAL: JWT_SECRET is using the fallback value in production. This is a critical security risk.");
    process.exit(1);
  } else {
    console.warn("WARNING: JWT_SECRET is using the fallback value. Do not use this in production.");
  }
}

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

const upload = multer({ storage: multer.memoryStorage() });

async function startServer() {
  // Everything scoped inside startServer — no global app references
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  // --- Database Setup ---
  const nativeDb = new Database("capmap.db");
  const db = {
    exec: (sql: string) => nativeDb.exec(sql),
    get: (sql: string, ...params: any[]) => nativeDb.prepare(sql).get(...params),
    all: (sql: string, ...params: any[]) => nativeDb.prepare(sql).all(...params),
    run: (sql: string, ...params: any[]) => nativeDb.prepare(sql).run(...params),
  };

  nativeDb.pragma("journal_mode = WAL");

  // --- Initialize Tables & Seed ---
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

  // --- Auth Middleware ---
  const authMiddleware = (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    // Only protect /api/* routes (except login)
    if (!req.path.startsWith("/api/")) return next();
    if (req.path === "/api/auth/login") return next();

    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      (req as any).user = decoded;
      next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
  app.use(authMiddleware);

  // =========================================================
  // API Routes
  // =========================================================

  // Health check
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // Auth
  app.post("/api/auth/login", async (req, res, next) => {
    try {
      const { email } = req.body;
      let user = db.get("SELECT * FROM users WHERE email = ?", email) as any;
      if (!user) {
        const id = Math.random().toString(36).substring(7);
        const password_hash = await bcrypt.hash("default_password", 10);
        db.run(
          "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)",
          id, email, password_hash, "user"
        );
        user = { id, email, role: "user" };
      }
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: "24h" }
      );
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      });
      res.json({ id: user.id, email: user.email, role: user.role });
    } catch (err) {
      next(err);
    }
  });

  // Capabilities
  app.get("/api/capabilities", (_req, res) => {
    const caps = db.all("SELECT * FROM capabilities");
    res.json(caps);
  });

  app.post("/api/capabilities", (req, res) => {
    const { name, domain, maturity_level } = req.body;
    const id = Math.random().toString(36).substring(7);
    db.run(
      "INSERT INTO capabilities (id, name, domain, maturity_level) VALUES (?, ?, ?, ?)",
      id, name, domain, maturity_level
    );
    res.json({ id, name, domain, maturity_level });
  });

  // Metrics Generation
  app.post("/api/metrics/generate", async (req, res, next) => {
    try {
      const { capabilityId } = req.body;
      const userId = (req as any).user.id;

      const today = new Date().toISOString().split("T")[0];
      const usage = db.get(
        "SELECT count FROM generation_usage WHERE user_id = ? AND date = ?",
        userId, today
      ) as any;
      if (usage && usage.count >= 50) {
        return res.status(429).json({
          error: "Daily AI generation limit reached. Please try again after 24 hours.",
        });
      }

      const capability = db.get(
        "SELECT * FROM capabilities WHERE id = ?",
        capabilityId
      ) as any;
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

      // 24h cache
      const cached = db.get(
        `SELECT * FROM metrics
         WHERE capability_id = ? AND prompt_hash = ?
           AND timestamp >= datetime('now', '-1 day')
         ORDER BY timestamp DESC LIMIT 1`,
        capabilityId, promptHash
      ) as any;
      if (cached) return res.json(JSON.parse(cached.kpi_json));

      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
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
      db.run(
        "INSERT INTO metrics (id, capability_id, prompt_hash, kpi_json) VALUES (?, ?, ?, ?)",
        id, capabilityId, promptHash, metricsJson
      );

      if (usage) {
        db.run(
          "UPDATE generation_usage SET count = count + 1 WHERE user_id = ? AND date = ?",
          userId, today
        );
      } else {
        db.run(
          "INSERT INTO generation_usage (user_id, date, count) VALUES (?, ?, 1)",
          userId, today
        );
      }

      res.json(JSON.parse(metricsJson!));
    } catch (error: any) {
      console.error(error);
      res.status(500).json({ error: "Failed to generate metrics", details: error.message });
    }
  });

  // Dashboard
  app.get("/api/dashboard", (req, res) => {
    const totalCapabilities = db.get("SELECT COUNT(*) as count FROM capabilities") as any;
    const totalSystems = db.get("SELECT COUNT(*) as count FROM it_assets") as any;
    const avgMaturity = db.get("SELECT AVG(maturity_level) as avg FROM capabilities") as any;

    const today = new Date().toISOString().split("T")[0];
    const userId = (req as any).user?.id || "anonymous";

    db.run(
      `INSERT INTO capability_snapshots (user_id, snapshot_date, avg_maturity)
       SELECT ?, ?, ?
       WHERE NOT EXISTS (SELECT 1 FROM capability_snapshots WHERE snapshot_date = ?)`,
      userId, today, avgMaturity.avg || 0, today
    );

    const domainDistribution = db.all(
      "SELECT domain as name, COUNT(*) as value FROM capabilities GROUP BY domain"
    );
    const snapshots = db.all(
      "SELECT snapshot_date as name, avg_maturity as value FROM capability_snapshots ORDER BY snapshot_date ASC"
    ) as any[];

    res.json({
      metrics: {
        totalCapabilities: totalCapabilities.count,
        totalSystems: totalSystems.count,
        avgMaturity: avgMaturity.avg ? avgMaturity.avg.toFixed(1) : 0,
        criticalGaps: 3,
      },
      charts: {
        domainDistribution: domainDistribution.length
          ? domainDistribution
          : [{ name: "None", value: 0 }],
        maturityTrend: [
          ...snapshots,
          {
            name: "Current",
            value: avgMaturity.avg ? parseFloat(avgMaturity.avg.toFixed(1)) : 0,
          },
        ],
      },
    });
  });

  // Visualizations
  app.post("/api/visualizations", async (req, res, next) => {
    try {
      const { prompt } = req.body;
      const userId = (req as any).user.id;

      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: {
          parts: [
            {
              text: `Create a professional business architecture diagram for: ${prompt}. Style: Clean, enterprise, blueprint.`,
            },
          ],
        },
        config: {
          imageConfig: { aspectRatio: "16:9" },
        },
      });

      let imageData: string | null = null;
      for (const part of response.candidates?.[0]?.content?.parts || []) {
        if ((part as any).inlineData) {
          imageData = `data:image/png;base64,${(part as any).inlineData.data}`;
          break;
        }
      }

      if (!imageData) {
        return res.status(500).json({ error: "Failed to generate image" });
      }

      const id = Math.random().toString(36).substring(7);
      db.run(
        "INSERT INTO visualizations (id, user_id, prompt, image_data) VALUES (?, ?, ?, ?)",
        id, userId, prompt, imageData
      );
      res.json({ id, prompt, imageData });
    } catch (error) {
      console.error(error);
      next(error);
    }
  });

  app.get("/api/visualizations", (req, res) => {
    const userId = (req as any).user.id;
    const history = db.all(
      "SELECT * FROM visualizations WHERE user_id = ? ORDER BY created_at DESC",
      userId
    );
    res.json(history);
  });

  // Interaction Logging
  app.post("/api/user/interactions", (req, res) => {
    const { userId, eventType, entityType, entityId, metadata } = req.body;
    db.run(
      "INSERT INTO interaction_events (user_id, event_type, entity_type, entity_id, metadata_json) VALUES (?, ?, ?, ?, ?)",
      userId, eventType, entityType, entityId, JSON.stringify(metadata)
    );
    res.json({ status: "ok" });
  });

  // Demo
  app.post("/api/demo/event", (req, res) => {
    const { userId, eventType, step } = req.body;
    db.run(
      "INSERT INTO demo_events (user_id, event_type, step) VALUES (?, ?, ?)",
      userId, eventType, step
    );
    res.json({ status: "ok" });
  });

  app.post("/api/demo/load", async (req, res, next) => {
    try {
      const csvString = `IT System,Capability,Business Process,Owner,Environment
Salesforce,Customer Management,Lead Processing,Sales,SaaS
AWS Lambda,Order Processing,Checkout Fulfillment,Engineering,Cloud
Snowflake,Analytics,Reporting,Data,Cloud
Stripe,Payment Processing,Billing,Finance,SaaS
Legacy CRM,Customer Management,Account Updates,Sales,On-Prem`;

      const parsed = Papa.parse(csvString, { header: true, skipEmptyLines: true });
      const rows = parsed.data as any[];
      let inserted = 0;

      const insertDemo = nativeDb.transaction(() => {
        for (const row of rows) {
          const assetName = row["IT System"];
          const capName = row["Capability"];
          const processName = row["Business Process"];
          const owner = row["Owner"];
          const env = row["Environment"];

          if (!capName) continue;

          const capId = `cap_${capName.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}`;
          db.run(
            "INSERT OR IGNORE INTO capabilities (id, name, domain, maturity_level) VALUES (?, ?, ?, ?)",
            capId, capName, "Demo", 3
          );

          if (assetName) {
            const assetId = `asset_${assetName.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}`;
            db.run(
              "INSERT OR IGNORE INTO it_assets (id, name, type, environment) VALUES (?, ?, ?, ?)",
              assetId, assetName, "System", env || "Production"
            );
            const relId = `rel_${assetId}_${capId}`;
            db.run(
              "INSERT OR IGNORE INTO relationships (id, source_id, source_type, target_id, target_type, relationship_type) VALUES (?, ?, ?, ?, ?, ?)",
              relId, assetId, "it_asset", capId, "capability", "supports"
            );
          }

          if (processName) {
            const processId = `proc_${processName.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}`;
            db.run(
              "INSERT OR IGNORE INTO processes (id, name, owner, domain, capability_id) VALUES (?, ?, ?, ?, ?)",
              processId, processName, owner || "Unknown", "Demo", capId
            );
          }

          inserted++;
        }

        const custMgmtMetrics = [
          { name: "Operational Efficiency", value: 45, unit: "%", description: "Low efficiency due to overlapping systems." },
          { name: "Automation Ratio", value: 30, unit: "%", description: "Manual sync required between Salesforce and Legacy CRM." },
          { name: "System Coupling", value: 0.82, unit: "Index", description: "High coupling between modern and legacy systems." },
          { name: "Failure Surface", value: 85, unit: "Risk Score", description: "High risk due to Legacy CRM dependencies." },
          { name: "Latency Risk", value: 70, unit: "Risk Score", description: "Data sync delays." },
          { name: "Strategic Importance", value: 95, unit: "Score", description: "Critical for revenue generation." },
          { name: "Modernization Priority", value: 100, unit: "Score", description: "Urgent need to retire Legacy CRM." },
          { name: "Value Contribution", value: 80, unit: "Score", description: "High value, but hampered by tech debt." },
        ];
        db.run(
          "INSERT OR REPLACE INTO metrics (capability_id, kpi_json) VALUES (?, ?)",
          "cap_customermanagement", JSON.stringify(custMgmtMetrics)
        );

        const orderProcMetrics = [
          { name: "Operational Efficiency", value: 92, unit: "%", description: "Highly efficient serverless architecture." },
          { name: "Automation Ratio", value: 98, unit: "%", description: "Fully automated via AWS Lambda." },
          { name: "System Coupling", value: 0.15, unit: "Index", description: "Loosely coupled microservices." },
          { name: "Failure Surface", value: 10, unit: "Risk Score", description: "Low risk, highly resilient." },
          { name: "Latency Risk", value: 5, unit: "Risk Score", description: "Real-time processing." },
          { name: "Strategic Importance", value: 90, unit: "Score", description: "Core operational capability." },
          { name: "Modernization Priority", value: 10, unit: "Score", description: "Already modernized." },
          { name: "Value Contribution", value: 95, unit: "Score", description: "Directly drives fulfillment." },
        ];
        db.run(
          "INSERT OR REPLACE INTO metrics (capability_id, kpi_json) VALUES (?, ?)",
          "cap_orderprocessing", JSON.stringify(orderProcMetrics)
        );
      });

      insertDemo();
      res.json({ success: true, rowsProcessed: inserted });
    } catch (err) {
      next(err);
    }
  });

  // Sample CSV
  app.get("/api/sample.csv", (_req, res) => {
    const csvContent =
      "Capability,IT System,Business Process,Owner,Environment\n" +
      "Customer Management,Salesforce,Lead Processing,Sales,SaaS\n" +
      "Order Fulfillment,AWS Lambda,Checkout Processing,Operations,Cloud\n";
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", 'attachment; filename="sample.csv"');
    res.send(csvContent);
  });

  // Bulk CSV Upload
  app.post("/api/capabilities/bulk", upload.single("file"), async (req, res, next) => {
    try {
      const file = (req as any).file;
      if (!file) return res.status(400).json({ error: "No file uploaded" });
      if (!file.originalname.toLowerCase().endsWith(".csv"))
        return res.status(400).json({ error: "File must be a .csv" });

      const csvString = file.buffer.toString("utf-8");
      if (!csvString.trim()) return res.status(400).json({ error: "CSV is empty" });

      const parsed = Papa.parse(csvString, { header: true, skipEmptyLines: true });
      if (parsed.errors.length > 0 && parsed.errors[0].code !== "TooFewFields")
        return res.status(400).json({ error: "Invalid CSV format", details: parsed.errors });

      const validation = validateCSVHeaders(parsed.meta.fields || []);
      if (!validation.isValid)
        return res.status(400).json({ error: validation.error });

      const rows = parsed.data as any[];
      if (rows.length === 0)
        return res.status(400).json({ error: "CSV must contain at least one row of data" });

      let inserted = 0;

      const insertBulk = nativeDb.transaction(() => {
        for (const row of rows) {
          const capKey = Object.keys(row).find(
            (k) => k.trim().toLowerCase() === "capability" || k.trim().toLowerCase() === "name"
          );
          if (!capKey) continue;

          const capName = row[capKey]?.trim();
          if (!capName) continue;

          const domainKey = Object.keys(row).find((k) => k.trim().toLowerCase() === "domain");
          const domain = domainKey ? row[domainKey] : "Imported";

          const ownerKey = Object.keys(row).find((k) => k.trim().toLowerCase() === "owner");
          const owner = ownerKey ? row[ownerKey] : "";

          const systemKey = Object.keys(row).find((k) => k.trim().toLowerCase() === "it system");
          const systemName = systemKey ? row[systemKey]?.trim() : "";

          const processKey = Object.keys(row).find((k) => k.trim().toLowerCase() === "business process");
          const processName = processKey ? row[processKey]?.trim() : "";

          const envKey = Object.keys(row).find((k) => k.trim().toLowerCase() === "environment");
          const env = envKey ? row[envKey]?.trim() : "Production";

          const capId = `cap_${capName.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}`;
          db.run(
            `INSERT OR REPLACE INTO capabilities
               (id, name, domain, maturity_level, owner, linked_system_ids, cost_center, sla_target_ms, last_reviewed)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            capId, capName, domain || "Imported", 1, owner, systemName, "", 0,
            new Date().toISOString()
          );

          if (systemName) {
            const assetId = `asset_${systemName.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}`;
            db.run(
              "INSERT OR IGNORE INTO it_assets (id, name, type, environment) VALUES (?, ?, ?, ?)",
              assetId, systemName, "System", env || "Production"
            );
            const relId = `rel_${assetId}_${capId}`;
            db.run(
              "INSERT OR IGNORE INTO relationships (id, source_id, source_type, target_id, target_type, relationship_type) VALUES (?, ?, ?, ?, ?, ?)",
              relId, assetId, "it_asset", capId, "capability", "supports"
            );
          }

          if (processName) {
            const processId = `proc_${processName.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}`;
            db.run(
              "INSERT OR IGNORE INTO processes (id, name, owner, domain, capability_id) VALUES (?, ?, ?, ?, ?)",
              processId, processName, owner || "Unknown", domain || "Imported", capId
            );
          }

          inserted++;
        }

        const today = new Date().toISOString().split("T")[0];
        const userId = (req as any).user?.id || "anonymous";
        const avgMaturityResult = db.get(
          "SELECT AVG(maturity_level) as avg FROM capabilities"
        ) as any;
        const avgMaturity = avgMaturityResult.avg || 0;
        db.run(
          `INSERT INTO capability_snapshots (user_id, snapshot_date, avg_maturity)
           VALUES (?, ?, ?)
           ON CONFLICT(snapshot_date) DO UPDATE
             SET avg_maturity = excluded.avg_maturity, user_id = excluded.user_id`,
          userId, today, avgMaturity
        );
      });

      insertBulk();

      if (inserted === 0)
        return res.status(400).json({ error: "No valid capability rows found to insert" });

      res.json({ success: true, rowsProcessed: inserted });
    } catch (err: any) {
      next(err);
    }
  });

  // Export
  app.post("/api/export", async (req, res, next) => {
    try {
      const { type } = req.body;

      const data = db.all(`
        SELECT c.name as Capability, c.domain as Domain, c.maturity_level as Maturity, m.kpi_json as Metrics
        FROM capabilities c
        LEFT JOIN metrics m ON c.id = m.capability_id
      `) as any[];

      const formattedData = data.map((row) => {
        const base: any = {
          Capability: row.Capability,
          Domain: row.Domain,
          Maturity: row.Maturity,
        };
        if (row.Metrics) {
          try {
            const metrics = JSON.parse(row.Metrics);
            metrics.forEach((m: any) => {
              base[m.name] = `${m.value} ${m.unit}`;
            });
          } catch { }
        }
        return base;
      });

      if (type === "csv") {
        const parser = new Parser();
        const csv = parser.parse(
          formattedData.length > 0 ? formattedData : [{ Message: "No data available" }]
        );
        res.header("Content-Type", "text/csv");
        res.attachment("export.csv");
        return res.send(csv);
      }

      if (type === "xlsx") {
        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet("Metrics");
        if (formattedData.length > 0) {
          sheet.columns = Object.keys(formattedData[0]).map((k) => ({ header: k, key: k }));
          formattedData.forEach((row) => sheet.addRow(row));
        } else {
          sheet.columns = [{ header: "Message", key: "Message" }];
          sheet.addRow({ Message: "No data available" });
        }
        res.header(
          "Content-Type",
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        );
        res.attachment("export.xlsx");
        await workbook.xlsx.write(res);
        return res.end();
      }

      res.status(400).send("Unsupported format");
    } catch (err) {
      next(err);
    }
  });

  // =========================================================
  // Static SPA serving — MUST come after all API routes
  // =========================================================
  app.use(express.static(distPath));

  // SPA fallback: serve index.html for any non-API route
  app.get(/^(?!\/api\/).*/, (_req, res) => {
    res.sendFile(path.join(distPath, "index.html"));
  });

  // =========================================================
  // Global Error Handler
  // =========================================================
  app.use(
    (
      err: any,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction
    ) => {
      console.error(err);
      res.status(500).json({ error: "Internal Server Error", details: err.message });
    }
  );

  app.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
  });
}

startServer();