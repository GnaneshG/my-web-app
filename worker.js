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
      // This endpoint uses no browser credentials; allow the hosted lexicon UI to call it.
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      const url = new URL(request.url);

      if (request.method !== "POST") {
        return new Response(JSON.stringify({ success: false, error: "Method not allowed" }), {
          status: 405,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const body = await request.json().catch(() => ({}));

      // Lexicon AI tasks run through this Worker so Gemini credentials stay server-side.
      if (url.pathname === "/api/ai-lookup" || url.pathname === "/ai-lookup") {
        const task = String(body.task || "");
        const term = String(body.word || body.term || "").trim().slice(0, 160);
        const jsonResponse = (payload, status = 200) => new Response(JSON.stringify(payload), {
          status,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
        const hasTamil = value => /[\u0B80-\u0BFF]/.test(String(value || ""));

        if (task === "translate_en_ta") {
          if (!term) return jsonResponse({ success: false, error: "An English term is required." }, 400);
          try {
            const googleUrl = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=ta&dt=t&ie=UTF-8&oe=UTF-8&q=${encodeURIComponent(term)}`;
            const googleResponse = await fetch(googleUrl);
            if (googleResponse.ok) {
              const googleData = await googleResponse.json();
              const tamil = (googleData?.[0] || []).map(part => part?.[0] || "").join("").trim();
              if (hasTamil(tamil)) return jsonResponse({ success: true, tamil, source: "Google Translate" });
            }
          } catch (error) {
            console.warn("Google Translate proxy failed:", error);
          }
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false, error: "GEMINI_API_KEY is not configured on the Worker serving this endpoint. Add it as a Worker secret and redeploy." }, 503);
          }
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: `Translate this English term or short phrase into concise, natural Tamil. Return only the Tamil translation, with no explanation.\n\nTerm: ${term}` }] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 100 }
              })
            });
            const data = await result.json().catch(() => ({}));
            const tamil = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            if (result.ok && hasTamil(tamil) && tamil.length <= 140 && !/[.!?\n\r]/.test(tamil)) {
              return jsonResponse({ success: true, tamil, source: "Gemini (unverified)" });
            }
            console.warn("Gemini translation request failed:", result.status, data?.error?.message || "No Tamil output");
            return jsonResponse({ success: false, error: result.ok ? "Gemini did not return a Tamil translation. Try again or enter the meaning manually." : `Gemini request failed (HTTP ${result.status}). Check that the Worker secret is valid and the Gemini API is enabled.` }, 502);
          } catch (error) {
            console.warn("Gemini translation proxy failed:", error);
            return jsonResponse({ success: false, error: "Could not reach Gemini. Check the Worker deployment and try again." }, 502);
          }
        }

        if (task === "classify_subject") {
          if (!term) return jsonResponse({ success: false, error: "A term is required." }, 400);
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false, error: "GEMINI_API_KEY is missing from the Worker." }, 503);
          }
          const categories = [
            "GS-1: Society & Culture", "GS-1: History & Heritage", "GS-1: Geography & Society",
            "GS-2: Polity & Governance", "GS-2: Social Justice", "GS-2: International Relations",
            "GS-3: Economy & Dev", "GS-3: Agriculture", "GS-3: Environment & Ecology",
            "GS-3: Disaster Management", "GS-3: Science & Tech", "GS-3: Internal Security",
            "GS-4: Ethics & Integrity", "Essay & Editorial Idioms"
          ];
          const prompt = `Assign exactly one UPSC subject category to the term. Use only one value from this JSON array: ${JSON.stringify(categories)}. Return only valid JSON: {"category":"exact category"}. Do not summarize or explain. Term: ${term}\nDefinition: ${String(body.definition || "").slice(0, 1200)}\nSynonyms: ${String(body.synonyms || "").slice(0, 300)}`;
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 80, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            if (!result.ok) return jsonResponse({ success: false, error: "Gemini could not classify this term." }, 502);
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            const category = categories.includes(parsed.category) ? parsed.category : "";
            if (!category) return jsonResponse({ success: false, error: "Gemini returned an invalid subject category." }, 502);
            return jsonResponse({ success: true, category, source: "Gemini AI subject classification" });
          } catch (error) {
            console.warn("Gemini subject classification failed:", error);
            return jsonResponse({ success: false, error: "Gemini could not return a subject category." }, 502);
          }
        }

        if (task === "word_search") {
          const query = String(body.query || "").trim().slice(0, 160);
          const entries = Array.isArray(body.entries) ? body.entries.slice(0, 500) : [];
          if (!query) return jsonResponse({ success: false, error: "A search word is required." }, 400);
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({ success: false, error: "GEMINI_API_KEY is missing from the Worker." }, 503);
          }
          const prompt = `Search the supplied Lexicon entries for terms or meanings related to the query. Do not summarize, define, or add text. Return only valid JSON: {"ids":["id", "id"]}. Include at most 30 matching IDs. Query: ${query}\nEntries: ${JSON.stringify(entries).slice(0, 20000)}`;
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 500, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            if (!result.ok) return jsonResponse({ success: false, error: "Gemini could not search the lexicon." }, 502);
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            const validIds = new Set(entries.map(entry => String(entry.id)));
            const ids = Array.isArray(parsed.ids)
              ? parsed.ids.map(value => String(value)).filter(id => validIds.has(id)).slice(0, 30)
              : [];
            return jsonResponse({ success: true, ids, source: "Gemini AI word search" });
          } catch (error) {
            console.warn("Gemini word search failed:", error);
            return jsonResponse({ success: false, error: "Gemini could not return search matches." }, 502);
          }
        }

        if (task === "dictionary_definition") {
          if (!term) return jsonResponse({ success: false, error: "An English term is required." }, 400);
          if (typeof env.GEMINI_API_KEY !== "string" || !env.GEMINI_API_KEY.trim()) {
            return jsonResponse({
              success: false,
              error: "GEMINI_API_KEY is missing from the Worker serving this request. Add it as a secret named GEMINI_API_KEY to the Worker, then deploy again."
            }, 503);
          }
          const prompt = `Give a concise, standard English dictionary definition for the term. Do not invent citations or claim a source. Return only valid JSON: {"definition":"...","partOfSpeech":"...","synonyms":["..."]}. Term: ${term}`;
          try {
            const result = await fetch(`${geminiGenerateContentUrl(env)}?key=${encodeURIComponent(env.GEMINI_API_KEY.trim())}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.2, maxOutputTokens: 300, responseMimeType: "application/json" }
              })
            });
            const data = await result.json().catch(() => ({}));
            if (!result.ok) {
              console.warn("Gemini Lexicon request failed:", result.status, data?.error?.message || "");
              return jsonResponse({ success: false, error: "Gemini could not complete the request." }, 502);
            }
            const raw = (data?.candidates?.[0]?.content?.parts || []).map(part => part?.text || "").join("").trim();
            const parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/gi, ""));
            if (task === "dictionary_definition") {
              const text = String(parsed.definition || "").trim().slice(0, 600);
              if (!text) return jsonResponse({ success: false, error: "Gemini returned no usable definition." }, 502);
              return jsonResponse({ success: true, definition: text, partOfSpeech: String(parsed.partOfSpeech || "").slice(0, 40), synonyms: Array.isArray(parsed.synonyms) ? parsed.synonyms.map(value => String(value).trim().slice(0, 60)).filter(Boolean).slice(0, 8) : [], source: "Gemini AI draft · verify" });
            }
            const fields = {};
            for (const key of ["nuance", "mainsRelevance", "pyqLinkage"]) {
              fields[key] = typeof parsed[key] === "string" ? parsed[key].trim().slice(0, 500) : "";
            }
            if (!fields.nuance && !fields.mainsRelevance && !fields.pyqLinkage) {
              return jsonResponse({ success: false, error: "Gemini returned no usable study notes." }, 502);
            }
            return jsonResponse({ success: true, ...fields, source: "Gemini AI draft · verify" });
          } catch (error) {
            console.warn("Gemini Lexicon generation failed:", error);
            return jsonResponse({ success: false, error: "Gemini returned an invalid response or is temporarily unavailable." }, 502);
          }
        }

        return jsonResponse({ success: false, error: "Unsupported lookup task." }, 400);
      }

      // ROUTE 1: Send OTP
      if (url.pathname === "/api/send-otp" || url.pathname === "/send-otp") {
        const email = String(body.email || url.searchParams.get("email") || "").trim();
        if (!email) return new Response(JSON.stringify({ success: false, error: "Email is required." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

        if (!env.RESET_STORE || !env.BREVO_API_KEY || !env.BREVO_SENDER_EMAIL) {
          return new Response(JSON.stringify({ success: false, error: "Password reset is not configured. Check the RESET_STORE binding and Brevo API key and verified sender settings." }), { status: 503, headers: { ...corsHeaders, "Content-Type": "application/json" } });
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
          console.error("Brevo password-reset email failed:", emailResponse.status);
          return new Response(JSON.stringify({ success: false, error: "The reset email could not be sent. Check the Brevo API key and verified sender." }), { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        return new Response(JSON.stringify({ success: true, requestId: requestId }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ROUTE 2: Verify OTP & Generate Custom Token securely
      if (url.pathname === "/api/verify-reset" || url.pathname === "/verify-reset") {
        const requestId = String(body.requestId || "").trim();
        const otp = String(body.otp || "").trim();
        if (!requestId || !otp) return new Response(JSON.stringify({ success: false, error: "Missing required fields." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

        let storedData = null;
        if (env.RESET_STORE) {
          const rawData = await env.RESET_STORE.get(requestId);
          if (rawData) storedData = JSON.parse(rawData);
        }

        if (!storedData) {
          return new Response(JSON.stringify({ success: false, error: "Invalid or expired verification session." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (storedData.attempts >= 3) {
          await env.RESET_STORE.delete(requestId);
          return new Response(JSON.stringify({ success: false, error: "Too many failed attempts. Please request a new code." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (storedData.otp !== otp) {
          storedData.attempts += 1;
          await env.RESET_STORE.put(requestId, JSON.stringify(storedData), { expirationTtl: 600 });
          return new Response(JSON.stringify({ success: false, error: "Invalid verification code." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const newPassword = body.newPassword;
        if (typeof newPassword !== "string" || newPassword.length < 6) {
          return new Response(JSON.stringify({ success: false, error: "A new password of at least 6 characters is required." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (!env.FIREBASE_CLIENT_EMAIL || !env.FIREBASE_PRIVATE_KEY) {
          return new Response(JSON.stringify({ success: false, error: "Password reset is not configured for Firebase Auth." }), { status: 503, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        let targetUid = await getFirebaseUidByEmail(storedData.email, env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY);

        if (!targetUid) {
          return new Response(JSON.stringify({ success: false, error: "User account not found in Firebase Auth." }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const accessToken = await getGoogleOAuthAccessToken(env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY);
        if (!accessToken) {
          return new Response(JSON.stringify({ success: false, error: "Could not authorize password update with Firebase Auth." }), { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const passwordResponse = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:update", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${accessToken}`
          },
          body: JSON.stringify({ localId: targetUid, password: newPassword, returnSecureToken: false })
        });
        if (!passwordResponse.ok) {
          console.error("Firebase password update failed:", passwordResponse.status, await passwordResponse.text());
          return new Response(JSON.stringify({ success: false, error: "Firebase Auth could not update the password. Please try again." }), { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const customToken = await createFirebaseCustomToken(env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY, targetUid);

        if (env.RESET_STORE) await env.RESET_STORE.delete(requestId);

        return new Response(JSON.stringify({ success: true, customToken: customToken }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      return new Response(JSON.stringify({ success: false, error: "Route not found" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ success: false, error: err.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }
};
