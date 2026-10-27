const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const authRoutes = require("./routes/auth.routes");
const uploadRoutes = require("./routes/upload.routes");
const signatureRoutes = require("./routes/signature.routes");
const teamRoutes = require("./routes/team.routes");
const publicTeamRoutes = require("./routes/publicTeam.routes");
const accountRoutes = require("./routes/account.routes");
const errorHandler = require("./middleware/errorHandler.middleware");

const app = express();

const trustProxyHops = parseInt(process.env.TRUST_PROXY_HOPS || "1", 10);
app.set("trust proxy", trustProxyHops);

// In non-production: Log trust proxy setting and log client IP diagnostics once on the first incoming request
if (process.env.NODE_ENV !== "production") {
  console.log(`[Proxy Config] trust proxy hops: ${trustProxyHops}`);
  let ipDiagnosticsLogged = false;
  app.use((req, res, next) => {
    if (!ipDiagnosticsLogged) {
      ipDiagnosticsLogged = true;
      const xForwardedFor = req.headers["x-forwarded-for"] || "none";
      console.log(
        `[Client IP Diagnostics] req.ip: "${req.ip}", X-Forwarded-For: "${xForwardedFor}", trust proxy: ${app.get("trust proxy")}`
      );
    }
    next();
  });
}

// Allowed origins for CORS whitelist
const defaultAllowedOrigins = [
  "https://www.sigsignature.com",
  "https://sigsignature.com",
];

if (process.env.FRONTEND_URL) {
  defaultAllowedOrigins.push(process.env.FRONTEND_URL.replace(/\/$/, ""));
}

if (process.env.NODE_ENV !== "production") {
  defaultAllowedOrigins.push(
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001"
  );
}

const allowedOriginsSet = new Set(defaultAllowedOrigins);

if (process.env.ALLOWED_ORIGINS) {
  process.env.ALLOWED_ORIGINS.split(",").forEach((origin) => {
    const trimmed = origin.trim().replace(/\/$/, "");
    if (trimmed) allowedOriginsSet.add(trimmed);
  });
}

app.use(helmet());
app.use(
  cors({
    origin: (origin, callback) => {
      // 1. Allow server-to-server, curl, mobile, or uptime/health monitors with no origin header
      if (!origin) {
        return callback(null, true);
      }

      const normalizedOrigin = origin.replace(/\/$/, "");

      // 2. Allow whitelisted origins
      if (allowedOriginsSet.has(normalizedOrigin)) {
        return callback(null, true);
      }

      // 3. In non-production, permit any localhost or 127.0.0.1 port
      if (
        process.env.NODE_ENV !== "production" &&
        (normalizedOrigin.startsWith("http://localhost:") ||
          normalizedOrigin.startsWith("http://127.0.0.1:"))
      ) {
        return callback(null, true);
      }

      // 4. Reject untrusted cross-origin requests
      return callback(null, false);
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: true, limit: "50kb" }));
app.use(cookieParser());

app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/uploads", uploadRoutes);
app.use("/api/v1/signatures", signatureRoutes);
app.use("/api/v1/team", teamRoutes);
app.use("/api/v1/public/team", publicTeamRoutes);
app.use("/api/v1/account", accountRoutes);

const healthHandler = (req, res) => {
  res.status(200).json({
    success: true,
    message: "SigSignature API is running",
    status: "UP",
  });
};

app.get("/health", healthHandler);
app.get("/", healthHandler);

// Centralized error handling middleware
app.use(errorHandler);

module.exports = app;
