import "dotenv/config";
import express from "express";
import cors from "cors";
import { verifyPaymobHmacHex } from "./lib/hmac.js";

const PORT = Number(process.env.PORT ?? 8787);
const BASE_URL =
  process.env.PAYMOB_BASE_URL?.replace(/\/$/, "") || "https://accept.paymob.com";
const SECRET_KEY = process.env.PAYMOB_SECRET_KEY?.trim();
const PUBLIC_KEY = process.env.PAYMOB_PUBLIC_KEY?.trim();
const HMAC_SECRET = process.env.PAYMOB_HMAC_SECRET?.trim();

/** Production Render URL — default Paymob `notification_url` unless `PAYMOB_NOTIFICATION_URL` is set. */
const DEFAULT_PUBLIC_API_ORIGIN = "https://unlimitedegypt.onrender.com";
const DEFAULT_PAYMOB_WEBHOOK = `${DEFAULT_PUBLIC_API_ORIGIN.replace(/\/$/, "")}/paymob/webhook`;

const SESSION_AMOUNTS_ENV = [
  ["quick-clarity", "PAYMOB_QUICK_CLARITY_CENTS"],
  ["business-advisory", "PAYMOB_BUSINESS_ADVISORY_CENTS"],
  ["monthly-mentorship", "PAYMOB_MONTHLY_MENTORSHIP_CENTS"],
];

function parseIntegrationIds() {
  const raw = process.env.PAYMOB_INTEGRATION_IDS || "";
  return raw
    .split(/[, ]+/)
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n > 0);
}

function amountCentsForSession(sessionId) {
  for (const [id, envName] of SESSION_AMOUNTS_ENV) {
    if (id !== sessionId) continue;
    const v = Number.parseInt(process.env[envName] ?? "", 10);
    return Number.isFinite(v) ? v : null;
  }
  return null;
}

function splitCustomerName(fullName, billing) {
  const first =
    billing?.first_name?.trim() ||
    fullName.trim().split(/\s+/)[0] ||
    "Customer";
  const rest = fullName.trim().split(/\s+/).slice(1).join(" ").trim();
  const last = billing?.last_name?.trim() || rest || "-";
  return { first_name: first, last_name: last };
}

const app = express();

const corsOrigin =
  process.env.PAYMOB_CORS_ORIGIN ||
  process.env.NEXT_PUBLIC_SITE_URL ||
  "http://localhost:3000";

app.use(
  cors({
    origin: corsOrigin === "*" ? true : corsOrigin,
    methods: ["GET", "POST", "OPTIONS"],
  })
);

/** Paymob webhooks arrive as JSON or urlencoded (`obj`, `hmac`). */
app.post(
  "/paymob/webhook",
  express.raw({ type: "*/*", limit: "2mb" }),
  (req, res) => {
    if (!HMAC_SECRET && process.env.PAYMOB_SKIP_HMAC_VERIFY !== "true") {
      console.error("[paymob] PAYMOB_HMAC_SECRET missing");
      return res.status(503).send("misconfigured");
    }

    try {
      const ct = String(req.headers["content-type"] || "").toLowerCase();
      let txnPayload;
      let receivedHmac;

      if (ct.includes("application/json")) {
        const parsed = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "{}");
        receivedHmac = parsed.hmac ?? parsed.signature;
        txnPayload =
          parsed.obj ??
          parsed.transaction ??
          parsed.data ??
          parsed;
      } else {
        const qs = new URLSearchParams(
          Buffer.isBuffer(req.body) ? req.body.toString("utf8") : ""
        );
        receivedHmac = qs.get("hmac") ?? qs.get("HMAC") ?? "";
        const objRaw = qs.get("obj") ?? qs.get("OBJ");
        txnPayload = objRaw
          ? JSON.parse(objRaw)
          : Object.fromEntries(qs.entries());
      }

      if (
        txnPayload &&
        typeof txnPayload === "object" &&
        txnPayload.transaction &&
        typeof txnPayload.transaction === "object"
      ) {
        txnPayload = txnPayload.transaction;
      }

      if (txnPayload && typeof txnPayload === "object") {
        txnPayload = { ...txnPayload };
        delete txnPayload.hmac;
        delete txnPayload.signature;
      }

      const { ok, skipped } = verifyPaymobHmacHex(
        txnPayload,
        receivedHmac,
        HMAC_SECRET
      );
      if (!ok) {
        console.warn("[paymob] webhook hmac mismatch", { skipped });
        return res.status(403).send("invalid hmac");
      }

      if (skipped) {
        console.warn("[paymob] webhook HMAC verify skipped (dev only)");
      }

      console.log("[paymob] verified callback", {
        merchant_order_id:
          txnPayload?.merchant_order_id ??
          txnPayload?.order ??
          txnPayload?.special_reference,
        success: txnPayload?.success,
        pending: txnPayload?.pending,
      });

      return res.status(200).send("ok");
    } catch (e) {
      console.error("[paymob] webhook error", e);
      return res.status(400).send("bad payload");
    }
  }
);

app.use(express.json({ limit: "1mb" }));

app.post("/paymob/intention", async (req, res) => {
  if (!SECRET_KEY || !PUBLIC_KEY) {
    return res.status(503).json({ error: "PAYMOB_SECRET_KEY/PAYMOB_PUBLIC_KEY missing" });
  }

  const { sessionId, customer, billing_data } = req.body || {};
  if (!sessionId || !customer?.email || !customer?.phone || !customer?.name) {
    return res.status(400).json({ error: "sessionId + customer{name,email,phone} required" });
  }

  const amount_cents = amountCentsForSession(sessionId);
  if (amount_cents == null || amount_cents <= 0) {
    return res.status(400).json({ error: `unknown session or amount not configured: ${sessionId}` });
  }

  const integrationIds = parseIntegrationIds();
  if (integrationIds.length === 0) {
    return res.status(503).json({ error: "PAYMOB_INTEGRATION_IDS missing" });
  }

  const currency = (process.env.PAYMOB_CURRENCY || "EGP").toUpperCase();
  const notify =
    process.env.PAYMOB_NOTIFICATION_URL?.trim() || DEFAULT_PAYMOB_WEBHOOK;
  const redirect =
    process.env.PAYMOB_REDIRECT_URL?.trim() ||
    `${String(corsOrigin).replace(/\/$/, "")}/payment/return`;

  const reference = `${sessionId}:${cryptoRandomId()}`;
  const { first_name, last_name } = splitCustomerName(customer.name, billing_data);

  const body = {
    amount: amount_cents,
    currency,
    payment_methods: integrationIds,
    items: [
      {
        name: `Booking — ${sessionId}`,
        amount: amount_cents,
        description: "Consulting session booking",
        quantity: 1,
      },
    ],
    billing_data: {
      apartment: "na",
      first_name,
      last_name,
      street: "na",
      building: "na",
      phone_number: String(customer.phone).trim(),
      city: "na",
      country: "EG",
      email: String(customer.email).trim(),
      floor: "na",
      state: "na",
    },
    special_reference: reference,
    extras: {
      session_id: sessionId,
      source: "koriem-web",
    },
  };

  if (notify) body.notification_url = notify;
  if (redirect) body.redirection_url = redirect;

  const paymobRes = await fetch(`${BASE_URL}/v1/intention/`, {
    method: "POST",
    headers: {
      Authorization: `Token ${SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const text = await paymobRes.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return res.status(502).json({ error: "paymob_invalid_json", detail: text.slice(0, 500) });
  }

  if (!paymobRes.ok) {
    return res.status(paymobRes.status).json({ error: "paymob_error", detail: json });
  }

  const clientSecret = json.client_secret;
  if (!clientSecret) {
    return res.status(502).json({ error: "missing client_secret", detail: json });
  }

  const unifiedCheckoutUrl = `${BASE_URL}/unifiedcheckout/?publicKey=${encodeURIComponent(
    PUBLIC_KEY
  )}&clientSecret=${encodeURIComponent(clientSecret)}`;

  return res.json({
    intentionOrderId: json.intention_order_id ?? json.order_id ?? null,
    clientSecret,
    unifiedCheckoutUrl,
    special_reference: reference,
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

function cryptoRandomId() {
  return `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
}

app.listen(PORT, () => {
  console.log(`koriem-paymob-api listening on ${PORT} (BASE_URL=${BASE_URL})`);
});
