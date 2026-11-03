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
  const data = await response.json();
  return data.access_token;
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
    const data = await response.json();
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
    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = [
      "https://tracker.studiz.workers.dev",
      "http://localhost:3000",
      "http://127.0.0.1:3000"
    ];
    
    const corsOrigin = allowedOrigins.includes(origin) ? origin : "https://tracker.studiz.workers.dev";

    const corsHeaders = { 
      "Access-Control-Allow-Origin": corsOrigin, 
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

      // ROUTE 1: Send OTP
      if (url.pathname === "/api/send-otp" || url.pathname === "/send-otp") {
        const email = body.email || url.searchParams.get("email");
        if (!email) return new Response(JSON.stringify({ success: false, error: "Email is required." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const requestId = crypto.randomUUID();

        if (env.RESET_STORE) {
          await env.RESET_STORE.put(requestId, JSON.stringify({ email, otp, attempts: 0 }), { expirationTtl: 600 });
        }

        if (env.BREVO_API_KEY) {
          await fetch("https://api.brevo.com/v3/smtp/email", {
            method: "POST",
            headers: { "accept": "application/json", "api-key": env.BREVO_API_KEY, "content-type": "application/json" },
            body: JSON.stringify({
              sender: { name: "TrackerCo Support", email: "gnaneshwaran2020@gmail.com" },
              to: [{ email: email }],
              subject: "Your TrackerCo Password Reset Code",
              textContent: `Your password reset verification code is: ${otp}. It expires in 10 minutes.`
            })
          });
        }

        return new Response(JSON.stringify({ success: true, requestId: requestId }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ROUTE 2: Verify OTP & Generate Custom Token securely
      if (url.pathname === "/api/verify-reset" || url.pathname === "/verify-reset") {
        const { requestId, otp } = body;
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

        let targetUid = null;
        if (env.FIREBASE_CLIENT_EMAIL && env.FIREBASE_PRIVATE_KEY) {
          targetUid = await getFirebaseUidByEmail(storedData.email, env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY);
        }

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
