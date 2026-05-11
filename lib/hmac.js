import crypto from "node:crypto";

/**
 * Verify Paymob transaction callbacks using SHA-512 HMAC (hex digest).
 *
 * Paymob publishes the exact concatenation rule in dashboard docs ([Egypt HMAC calculations](https://developers.paymob.com/egypt/manage-callback/transaction-processed-calculations-for-hmac)).
 * If verification fails against a live callback, inspect the payload (e.g. [webhook testing tool](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/webhook-testing-tool))
 * and align this helper with Paymob's field order for your callback type — or set PAYMOB_HMAC_MODE=experimental_order and PAYMOB_HMAC_FIELDS to a comma-separated key list matching the docs.
 */

function flattenNestedObject(obj, prefix = "") {
  const out = {};
  if (!obj || typeof obj !== "object") return out;
  for (const [k, v] of Object.entries(obj)) {
    if (k === "hmac") continue;
    const key = prefix ? `${prefix}.${k}` : k;
    if (v === null || v === undefined) {
      out[key] = "";
    } else if (typeof v === "object" && !Array.isArray(v)) {
      Object.assign(out, flattenNestedObject(v, key));
    } else if (Array.isArray(v)) {
      out[key] = JSON.stringify(v);
    } else if (typeof v === "boolean" || typeof v === "number") {
      out[key] = String(v);
    } else {
      out[key] = String(v);
    }
  }
  return out;
}

function concatenateSortedKeys(flat) {
  return Object.keys(flat)
    .sort()
    .map((name) => flat[name])
    .join("");
}

function concatenateOrderedFields(flat, orderedKeys) {
  return orderedKeys.map((name) => flat[name] ?? "").join("");
}

function computeHmacSecret(secret) {
  return String(secret ?? "").trim();
}

export function computePaymobHmacHex(payloadObject, hmacSecret, options = {}) {
  const secret = computeHmacSecret(hmacSecret);
  if (!secret) return null;
  const flat = flattenNestedObject(payloadObject);
  const mode = process.env.PAYMOB_HMAC_MODE || "sorted_flatten";
  let concat;
  if (mode === "experimental_order" && process.env.PAYMOB_HMAC_FIELDS) {
    const fields = process.env.PAYMOB_HMAC_FIELDS.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    concat = concatenateOrderedFields(flat, fields);
  } else {
    concat = concatenateSortedKeys(flat);
  }
  return crypto.createHmac("sha512", secret).update(concat).digest("hex");
}

export function timingSafeEqualHex(a, b) {
  try {
    const ba = Buffer.from(String(a ?? "").trim(), "hex");
    const bb = Buffer.from(String(b ?? "").trim(), "hex");
    if (ba.length !== bb.length || ba.length === 0) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export function verifyPaymobHmacHex(payloadObject, receivedHmac, hmacSecret) {
  const skip =
    process.env.NODE_ENV !== "production" &&
    process.env.PAYMOB_SKIP_HMAC_VERIFY === "true";
  if (skip) return { ok: true, skipped: true };
  const expected = computePaymobHmacHex(payloadObject, hmacSecret);
  if (!expected || !receivedHmac) return { ok: false, skipped: false };
  const ok = timingSafeEqualHex(expected.toLowerCase(), receivedHmac.toLowerCase());
  return { ok, skipped: false };
}
