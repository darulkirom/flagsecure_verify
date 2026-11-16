// Cloudflare Worker: verifikasi integritas APK + pengiriman konten terenkripsi per-sesi.
// Secret : HMAC_KEY (wajib), SECRET_CONTENT (teks rahasia yang dikirim).
// Vars   : EXPECTED_ENTRIES, EXPECTED_SIZE, EXPECTED_DEX, EXPECTED_SIG.
// Opsional: binding KV "NONCES" supaya nonce sekali pakai (anti-replay).

const enc = new TextEncoder();

const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });

// ECDH(P-256) dengan kunci publik sesi dari app -> AES-GCM, terikat ke nonce.
async function sealForSession(pubB64, nonce, plaintext) {
  const clientPub = await crypto.subtle.importKey(
    "spki", b64d(pubB64), { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const eph = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: clientPub }, eph.privateKey, 256)
  );

  const label = enc.encode("flagsecure-v1");
  const nb = enc.encode(nonce);
  const material = new Uint8Array(label.length + shared.length + nb.length);
  material.set(label, 0);
  material.set(shared, label.length);
  material.set(nb, label.length + shared.length);

  const keyBytes = await crypto.subtle.digest("SHA-256", material);
  const aes = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: nb }, aes, enc.encode(plaintext)
  );
  const serverPub = await crypto.subtle.exportKey("spki", eph.publicKey);
  return { pub: b64e(serverPub), iv: b64e(iv), ct: b64e(ct) };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === "/nonce") {
      const base = `${Date.now()}.${crypto.randomUUID()}`;
      return json({ nonce: `${base}.${await hmac(env.HMAC_KEY, base)}` });
    }

    if (url.pathname === "/verify" && req.method === "POST") {
      const r = await req.json().catch(() => null);
      if (!r) return json({ ok: false, reason: "bad_request" }, 400);

      const parts = String(r.nonce || "").split(".");
      if (parts.length !== 3) return json({ ok: false, reason: "bad_nonce" }, 400);
      const [ts, rnd, mac] = parts;
      if (mac !== (await hmac(env.HMAC_KEY, `${ts}.${rnd}`)))
        return json({ ok: false, reason: "bad_nonce" }, 400);
      if (Date.now() - Number(ts) > 60000)
        return json({ ok: false, reason: "nonce_expired" }, 400);

      // Nonce sekali pakai (butuh KV). Tanpa binding, hanya dibatasi 60 detik.
      if (env.NONCES) {
        const k = `n:${rnd}`;
        if (await env.NONCES.get(k)) return json({ ok: false, reason: "replay" }, 400);
        await env.NONCES.put(k, "1", { expirationTtl: 120 });
      }

      const seen = { entries: r.entries, size: r.size, dex: r.dex, sig: r.sig };

      // Mode belajar: belum ada nilai acuan diset, server cuma menampilkan apa yang dilihat.
      if (!env.EXPECTED_ENTRIES && !env.EXPECTED_SIZE && !env.EXPECTED_DEX && !env.EXPECTED_SIG)
        return json({ ok: false, reason: "learn_mode", seen });

      const fails = [];
      if (env.EXPECTED_ENTRIES && String(r.entries) !== String(env.EXPECTED_ENTRIES)) fails.push("entries");
      if (env.EXPECTED_SIZE && String(r.size) !== String(env.EXPECTED_SIZE)) fails.push("size");
      if (env.EXPECTED_DEX && r.dex !== env.EXPECTED_DEX) fails.push("dex");
      if (env.EXPECTED_SIG && r.sig !== env.EXPECTED_SIG) fails.push("sig");
      if (r.flagIntact === false || r.hook === true) fails.push("runtime");

      if (fails.length) return json({ ok: false, reason: "tamper", fails, seen });

      // Lolos: konten dikirim terenkripsi dengan kunci sesi (tidak ada kunci statis).
      try {
        const sealed = await sealForSession(
          String(r.pub || ""),
          String(r.nonce),
          env.SECRET_CONTENT || "KONTEN RAHASIA\n1234 5678 9012"
        );
        return json({ ok: true, ...sealed });
      } catch (e) {
        return json({ ok: false, reason: "bad_pub" }, 400);
      }
    }

    return json({ error: "not_found" }, 404);
  },
};
                           
