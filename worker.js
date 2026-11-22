function pemToBinary(pem) {
  const cleanPem = pem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\\n/g, '\n');
  const base64 = cleanPem.replace(/\s/g, '');
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return bytes.buffer;
}

function base64UrlEncode(str) {
  return btoa(typeof str === 'string' ? str : JSON.stringify(str)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function geminiGenerateContentUrl(env) {
  const configuredModel = typeof env.GEMINI_MODEL === 'string' ? env.GEMINI_MODEL.trim() : '';
  const model = /^[a-zA-Z0-9._-]+$/.test(configuredModel) ? configuredModel : 'gemini-2.5-flash';
  return `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
}

async function signJwt(clientEmail, privateKeyPem, aud, scope) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: aud,
    scope: scope,
    iat: now,
    exp: now + 3600
  };
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const keyBuffer = pemToBinary(privateKeyPem);
  const privateKey = await crypto.subtle.importKey('pkcs8', keyBuffer, { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, false, ['sign']);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(signingInput));

  const uint8Sig = new Uint8Array(signature);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < uint8Sig.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, uint8Sig.subarray(i, i + chunkSize));
  }
  const encodedSignature = btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${signingInput}.${encodedSignature}`;
}

async function getGoogleOAuthAccessToken(clientEmail, privateKeyPem) {
  const jwt = await signJwt(clientEmail, privateKeyPem, 'https://oauth2.googleapis.com/token', 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/cloud-platform');
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  const data = await response.json().catch(() => ({}));
  return data.access_token || null;
}

async function verifyFirebaseIdToken(idToken, env) {
  if (!idToken || !env.FIREBASE_CLIENT_EMAIL || !env.FIREBASE_PRIVATE_KEY) return null;
  try {
    const accessToken = await getGoogleOAuthAccessToken(env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY);
    if (!accessToken) return null;
    const response = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({ idToken })
    });
    const data = await response.json().catch(() => ({}));
    if (response.ok && Array.isArray(data.users) && data.users.length > 0) {
      return {
        uid: data.users[0].localId,
        email: String(data.users[0].email || '').toLowerCase()
      };
    }
  } catch (err) {
    console.error('Firebase ID token verification failed:', err);
  }
  return null;
}

async function createFirebaseCustomToken(clientEmail, privateKeyPem, uid) {
  const jwt = await signJwt(clientEmail, privateKeyPem, 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit', '');
  const parts = jwt.split('.');
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  payload.uid = uid;
  delete payload.scope;
  const encodedHeader = parts[0];
  const encodedPayload = base64UrlEncode(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const keyBuffer = pemToBinary(privateKeyPem);
  const privateKey = await crypto.subtle.importKey('pkcs8', keyBuffer, { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, false, ['sign']);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(signingInput));

  const uint8Sig = new Uint8Array(signature);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < uint8Sig.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, uint8Sig.subarray(i, i + chunkSize));
  }
  const encodedSignature = btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${signingInput}.${encodedSignature}`;
}

async function getFirebaseUidByEmail(email, clientEmail, privateKeyPem) {
  try {
    const accessToken = await getGoogleOAuthAccessToken(clientEmail, privateKeyPem);
    if (!accessToken) return null;

    const response = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup', {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify({ email: [email] })
    });
    const data = await response.json().catch(() => ({}));
    if (data.users && data.users.length > 0) {
      return data.users[0].localId;
    }
  } catch (err) {
    console.error("Error looking up Firebase user via Admin API:", err);
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const jsonResponse = (payload, status = 200) => new Response(JSON.stringify(payload), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

    try {
      const url = new URL(request.url);

      // ROUTE: Fast & Secure Email-Keyed Cloud Backup (KV + Optional Email Attachment)
      if (url.pathname === "/api/backup-sync" || url.pathname === "/backup-sync") {
        const authHeader = request.headers.get("Authorization") || "";
        const idToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
        const verifiedUser = await verifyFirebaseIdToken(idToken, env);

        if (!verifiedUser || !verifiedUser.email) {
          return jsonResponse({ success: false, error: "Unauthorized: Valid Firebase sign-in token required." }, 401);
        }

        const kvKey = `backup:email:${verifiedUser.email}`;

        if (request.method === "GET") {
          if (!env.RESET_STORE) return jsonResponse({ success: false, error: "Backup KV store not configured." }, 503);
          const raw = await env.RESET_STORE.get(kvKey);
          return jsonResponse({ success: true, backup: raw ? JSON.parse(raw) : null });
        }

        if (request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const backupRecord = {
            email: verifiedUser.email,
            uid: verifiedUser.uid,
            updatedAtMs: Number(body.updatedAtMs) || Date.now(),
            savedAt: new Date().toISOString(),
            state: body.state || {}
          };

          if (env.RESET_STORE) {
            await env.RESET_STORE.put(kvKey, JSON.stringify(backupRecord));
          }

          // Optional Brevo Email Backup Snapshot when requested or once per 24h
          if (body.sendEmail && env.BREVO_API_KEY && env.BREVO_SENDER_EMAIL) {
            const lexiconCount = Array.isArray(backupRecord.state?.cse_lexicon_v5) ? backupRecord.state.cse_lexicon_v5.length : 0;
            const jsonBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(backupRecord, null, 2))));
            await fetch("https://api.brevo.com/v3/smtp/email", {
              method: "POST",
              headers: {
                "accept": "application/json",
                "api-key": env.BREVO_API_KEY,
                "content-type": "application/json"
              },
              body: JSON.stringify({
                sender: { name: String(env.BREVO_SENDER_NAME || "TrackerCo Backup").trim(), email: String(env.BREVO_SENDER_EMAIL).trim() },
                to: [{ email: verifiedUser.email }],
                subject: `TrackerCo & Lexicon Backup (${new Date().toISOString().slice(0, 10)})`,
                textContent: `Your TrackerCo study & Lexicon data (${lexiconCount} indexed words) has been securely backed up for ${verifiedUser.email}.`,
                attachment: [{
                  content: jsonBase64,
                  name: `trackerco-backup-${new Date().toISOString().slice(0, 10)}.json`
                }]
              })
            }).catch(e => console.warn("Brevo backup email skipped:", e));
          }

          return jsonResponse({ success: true, email: verifiedUser.email, savedAt: backupRecord.savedAt });
        }
      }

      if (request.method !== "POST") {
        return jsonResponse({ success: false, error: "Method not allowed" }, 405);
      }

      const body = await request.json().catch(() => ({}));

      // Lexicon AI & Classification Tasks
      if (url.pathname === "/api/ai-lookup" || url.pathname === "/ai-lookup") {
        const task = String(body.task || "");
        const term = String(body.word || body.term || "").trim().slice(0, 160);
        const hasTamil = value => /[\u0B80-\u0BFF]/.test(String(value || ""));

        if (task === "translate_en_ta") {
          if (!term) return jsonResponse({ success: false, error: "An English term is required." }, 400);
          try {
            const googleUrl = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=ta&dt=t&dt=bd&ie=UTF-8&oe=UTF-8&q=${encodeURIComponent(term)}`;
            const googleResponse = await fetch(googleUrl);
            if (googleResponse.ok) {
              const googleData = await googleResponse.json();
              const tamil = (googleData?.[0] || []).map(part => part?.[0] || "").join("").trim();
              if (hasTamil(tamil)) return jsonResponse({ success: true, tamil, source: "Exact Tamil Dictionary" });
            }
          } catch (_) {}
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false, error: "GEMINI_API_KEY is not configured on the Worker." }, 503);
          }
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: `Translate this English UPSC term into exact, formal Tamil dictionary equivalent. Return only the Tamil term.\n\nTerm: ${term}` }] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 100 }
              })
            });
            const data = await result.json().catch(() => ({}));
            const tamil = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            if (result.ok && hasTamil(tamil) && tamil.length <= 140) {
              return jsonResponse({ success: true, tamil, source: "Tamil Glossary" });
            }
            return jsonResponse({ success: false, error: "No Tamil translation returned." }, 502);
          } catch (_) {
            return jsonResponse({ success: false, error: "Could not reach Gemini." }, 502);
          }
        }

        if (task === "classify_subject") {
          if (!term || typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false }, 400);
          }
          const categories = [
            "GS-1: Society & Culture", "GS-1: History & Heritage", "GS-1: Geography & Society",
            "GS-2: Polity & Governance", "GS-2: Social Justice", "GS-2: International Relations",
            "GS-3: Economy & Dev", "GS-3: Agriculture", "GS-3: Environment & Ecology",
            "GS-3: Disaster Management", "GS-3: Science & Tech", "GS-3: Internal Security",
            "GS-4: Ethics & Integrity", "Essay & Editorial Idioms"
          ];
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: `Classify this UPSC term into exactly one category from: ${categories.join(", ")}. Return JSON: {"category":"..."}. Term: ${term}. Definition: ${String(body.definition || "").slice(0, 300)}` }] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 80, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(p => p?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            if (categories.includes(parsed.category)) {
              return jsonResponse({ success: true, category: parsed.category });
            }
          } catch (_) {}
          return jsonResponse({ success: false }, 422);
        }

        if (task === "upsc_pyq_glossary") {
          if (!term || typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false }, 400);
          }
          try {
            const prompt = `For the English UPSC glossary term "${term}" (${String(body.category || "")}), return JSON with two concise, strictly factual fields: {"pyqPlacement": "How UPSC frames or tests this term in Prelims statements or Mains directives (2 concise sentences, no fabricated exam years)", "glossaryRole": "Core conceptual meaning in ${String(body.category || "UPSC")} glossaries (1-2 concise sentences)"}. Definition: ${String(body.definition || "").slice(0, 300)}`;
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.2, maxOutputTokens: 350, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(p => p?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            return jsonResponse({
              success: true,
              pyqPlacement: String(parsed.pyqPlacement || "").trim().slice(0, 500),
              glossaryRole: String(parsed.glossaryRole || "").trim().slice(0, 500)
            });
          } catch (_) {}
          return jsonResponse({ success: false }, 422);
        }

        if (task === "document_analysis") {
          const documentText = String(body.text || "").trim().slice(0, 24000);
          const filename = String(body.filename || "Uploaded PDF").trim().slice(0, 160);
          if (!documentText) return jsonResponse({ success: false, error: "No extractable document text was supplied." }, 400);
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false, error: "GEMINI_API_KEY is missing from the Worker." }, 503);
          }
          const prompt = `Create concise, useful study notes from the supplied study-document text. Return valid JSON with fields: {"summary":"...","keyTerms":["term — explanation"],"studyPoints":["..."],"questions":["..."]}. Filename: ${filename}\n\nDocument text:\n${documentText}`;
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.2, maxOutputTokens: 1200, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            if (!result.ok) return jsonResponse({ success: false, error: "Gemini could not analyze this document." }, 502);
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            const cleanList = value => Array.isArray(value) ? value.map(item => String(item).trim().slice(0, 260)).filter(Boolean).slice(0, 8) : [];
            return jsonResponse({
              success: true,
              summary: String(parsed.summary || "").trim().slice(0, 900),
              keyTerms: cleanList(parsed.keyTerms),
              studyPoints: cleanList(parsed.studyPoints),
              questions: cleanList(parsed.questions),
              source: "Gemini AI draft · verify"
            });
          } catch (_) {
            return jsonResponse({ success: false, error: "Gemini returned an invalid response." }, 502);
          }
        }

        if (task === "dictionary_definition" || task === "study_enrichment") {
          if (!term) return jsonResponse({ success: false, error: "An English term is required." }, 400);
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false, error: "GEMINI_API_KEY is missing from the Worker." }, 503);
          }
          const definition = String(body.definition || "").trim().slice(0, 1200);
          const category = String(body.category || "").trim().slice(0, 100);
          const tamil = String(body.tamil || "").trim().slice(0, 160);
          const prompt = task === "dictionary_definition"
            ? `Give a concise, standard English dictionary definition for the term. Return only valid JSON: {"definition":"...","partOfSpeech":"...","synonyms":["..."]}. Term: ${term}`
            : `Prepare a cautious UPSC study-note draft. Return only valid JSON with string fields "nuance", "mainsRelevance", and "pyqLinkage". Term: ${term}\nEnglish definition: ${definition}\nGS category: ${category}\nTamil meaning: ${tamil}`;
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.2, maxOutputTokens: task === "dictionary_definition" ? 300 : 600, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            if (!result.ok) return jsonResponse({ success: false, error: "Gemini could not complete the request." }, 502);
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            if (task === "dictionary_definition") {
              const text = String(parsed.definition || "").trim().slice(0, 600);
              if (!text) return jsonResponse({ success: false, error: "No usable definition." }, 502);
              return jsonResponse({
                success: true,
                definition: text,
                partOfSpeech: String(parsed.partOfSpeech || "").slice(0, 40),
                synonyms: Array.isArray(parsed.synonyms) ? parsed.synonyms.map(v => String(v).trim().slice(0, 60)).filter(Boolean).slice(0, 8) : [],
                source: "Glossary Dictionary"
              });
            }
            return jsonResponse({
              success: true,
              nuance: typeof parsed.nuance === "string" ? parsed.nuance.trim().slice(0, 500) : "",
              mainsRelevance: typeof parsed.mainsRelevance === "string" ? parsed.mainsRelevance.trim().slice(0, 500) : "",
              pyqLinkage: typeof parsed.pyqLinkage === "string" ? parsed.pyqLinkage.trim().slice(0, 500) : "",
              source: "UPSC Glossary"
            });
          } catch (_) {
            return jsonResponse({ success: false, error: "Gemini temporarily unavailable." }, 502);
          }
        }

        return jsonResponse({ success: false, error: "Unsupported lookup task." }, 400);
      }

      // ROUTE 1: Send OTP
      if (url.pathname === "/api/send-otp" || url.pathname === "/send-otp") {
        const email = String(body.email || url.searchParams.get("email") || "").trim();
        if (!email) return jsonResponse({ success: false, error: "Email is required." }, 400);

        if (!env.RESET_STORE || !env.BREVO_API_KEY || !env.BREVO_SENDER_EMAIL) {
          return jsonResponse({ success: false, error: "Password reset is not configured." }, 503);
        }

        const senderEmail = String(env.BREVO_SENDER_EMAIL).trim();
        const senderName = String(env.BREVO_SENDER_NAME || "TrackerCo Support").trim();
        const otp = crypto.getRandomValues(new Uint32Array(1))[0] % 900000 + 100000;
        const requestId = crypto.randomUUID();
        await env.RESET_STORE.put(requestId, JSON.stringify({ email, otp: String(otp), attempts: 0 }), { expirationTtl: 600 });

        const emailResponse = await fetch("https://api.brevo.com/v3/smtp/email", {
          method: "POST",
          headers: { "accept": "application/json", "api-key": env.BREVO_API_KEY, "content-type": "application/json" },
          body: JSON.stringify({
            sender: { name: senderName, email: senderEmail },
            to: [{ email: email }],
            subject: "Your TrackerCo Password Reset Code",
            textContent: `Your password reset verification code is: ${otp}. It expires in 10 minutes.`
          })
        });
        if (!emailResponse.ok) {
          await env.RESET_STORE.delete(requestId);
          return jsonResponse({ success: false, error: "The reset email could not be sent." }, 502);
        }

        return jsonResponse({ success: true, requestId: requestId }, 200);
      }

      // ROUTE 2: Verify OTP & Generate Custom Token securely
      if (url.pathname === "/api/verify-reset" || url.pathname === "/verify-reset") {
        const requestId = String(body.requestId || "").trim();
        const otp = String(body.otp || "").trim();
        if (!requestId || !otp) return jsonResponse({ success: false, error: "Missing required fields." }, 400);

        let storedData = null;
        if (env.RESET_STORE) {
          const rawData = await env.RESET_STORE.get(requestId);
          if (rawData) storedData = JSON.parse(rawData);
        }

        if (!storedData) return jsonResponse({ success: false, error: "Invalid or expired verification session." }, 400);
        if (storedData.attempts >= 3) {
          await env.RESET_STORE.delete(requestId);
          return jsonResponse({ success: false, error: "Too many failed attempts." }, 400);
        }
        if (storedData.otp !== otp) {
          storedData.attempts += 1;
          await env.RESET_STORE.put(requestId, JSON.stringify(storedData), { expirationTtl: 600 });
          return jsonResponse({ success: false, error: "Invalid verification code." }, 400);
        }

        const newPassword = body.newPassword;
        if (typeof newPassword !== "string" || newPassword.length < 6) {
          return jsonResponse({ success: false, error: "A new password of at least 6 characters is required." }, 400);
        }

        if (!env.FIREBASE_CLIENT_EMAIL || !env.FIREBASE_PRIVATE_KEY) {
          return jsonResponse({ success: false, error: "Password reset is not configured for Firebase Auth." }, 503);
        }

        let targetUid = await getFirebaseUidByEmail(storedData.email, env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY);
        if (!targetUid) return jsonResponse({ success: false, error: "User account not found in Firebase Auth." }, 404);

        const accessToken = await getGoogleOAuthAccessToken(env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY);
        if (!accessToken) return jsonResponse({ success: false, error: "Could not authorize password update." }, 502);

        const passwordResponse = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:update", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${accessToken}` },
          body: JSON.stringify({ localId: targetUid, password: newPassword, returnSecureToken: false })
        });
        if (!passwordResponse.ok) return jsonResponse({ success: false, error: "Firebase Auth could not update the password." }, 502);

        const customToken = await createFirebaseCustomToken(env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY, targetUid);
        if (env.RESET_STORE) await env.RESET_STORE.delete(requestId);

        return jsonResponse({ success: true, customToken: customToken }, 200);
      }

      return jsonResponse({ success: false, error: "Route not found" }, 404);
    } catch (err) {
      return jsonResponse({ success: false, error: err.message }, 500);
    }
  }
};
