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
const referralRoutes = require("./routes/referral.routes");
const integrationRoutes = require("./routes/integration.routes");
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
  "https://staging.sigsignature.com",
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

app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  })
);
app.use(
  cors({
    origin: (origin, callback) => {
      // 1. Allow server-to-server, curl, mobile, or uptime/health monitors with no origin header
      if (!origin) {
        return callback(null, true);
      }

      const normalizedOrigin = origin.replace(/\/$/, "");

      // 2. Allow whitelisted origins or *.sigsignature.com subdomains
      if (
        allowedOriginsSet.has(normalizedOrigin) ||
        /^https:\/\/([a-z0-9-]+\.)*sigsignature\.com$/.test(normalizedOrigin)
      ) {
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
app.use("/api/v1/referrals", referralRoutes);
app.use("/api/v1/integrations", integrationRoutes);

// OpenAPI & API Documentation Endpoints
const openApiSpec = require("./openapi.json");
const openApiHandler = (req, res) => {
  res.status(200).json(openApiSpec);
};
const docsHtmlHandler = (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html>
  <head>
    <title>SigSignature API Docs</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" crossorigin="anonymous"></script>
    <script>
      window.onload = () => {
        window.ui = SwaggerUIBundle({
          url: '/api/v1/openapi.json',
          dom_id: '#swagger-ui',
        });
      };
    </script>
  </body>
</html>`);
};

app.get("/openapi.json", openApiHandler);
app.get("/api/v1/openapi.json", openApiHandler);
app.get("/api-docs", docsHtmlHandler);
app.get("/docs", docsHtmlHandler);
app.get("/swagger", docsHtmlHandler);

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
