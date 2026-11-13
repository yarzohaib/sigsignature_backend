/**
 * Accepts a candidate frontend origin and returns it only when it is one of our own
 * sites (production, staging, Vercel previews, localhost). Used to decide where to
 * send the browser back to after a third party consent screen.
 */
function sanitizeFrontendOrigin(originCandidate) {
  if (!originCandidate || typeof originCandidate !== "string") {
    return null;
  }
  try {
    const parsed = new URL(originCandidate);
    const host = parsed.hostname.toLowerCase();
    const isLocal = host === "localhost" || host === "127.0.0.1";
    if (isLocal) {
      return process.env.NODE_ENV === "production" ? null : parsed.origin;
    }
    if (parsed.protocol !== "https:") {
      return null;
    }
    if (
      host === "sigsignature.com" ||
      host.endsWith(".sigsignature.com") ||
      host.endsWith(".vercel.app")
    ) {
      return parsed.origin;
    }
  } catch (_) {
    // fall through
  }
  return null;
}

module.exports = { sanitizeFrontendOrigin };
