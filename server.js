require("dotenv").config();
const path = require("path");
const express = require("express");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("Missing Supabase env vars. Set SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY in .env");
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false }
});

const supabasePublic = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false }
});

app.use(express.json({ limit: "6mb" }));

function usernameToEmail(username) {
  const safe = String(username).trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
  return safe ? `${safe}@demo.local` : "";
}

app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }
  try {
    const email = usernameToEmail(username);
    if (!email) return res.status(400).json({ error: "Invalid username" });

    const { data: createData, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username }
    });

    if (createError) {
      return res.status(400).json({ error: createError.message });
    }

    const userId = createData.user.id;

    await supabaseAdmin.from("profiles").upsert({
      user_id: userId,
      username,
      role: "user"
    }, { onConflict: "user_id" });

    const { data: authData, error: authError } = await supabasePublic.auth.signInWithPassword({
      email,
      password
    });

    if (authError || !authData.session) {
      return res.status(400).json({ error: "Signup succeeded, but login failed." });
    }

    return res.json({
      ok: true,
      session: authData.session,
      user: authData.user
    });
  } catch (err) {
    return res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }
  try {
    const email = usernameToEmail(username);
    if (!email) return res.status(400).json({ error: "Invalid username" });

    const { data: usersData, error: listError } = await supabaseAdmin.auth.admin.listUsers({
      page: 1,
      perPage: 1000
    });

    if (!listError && usersData && Array.isArray(usersData.users)) {
      const existing = usersData.users.find(u => u.email === email);
      if (existing && !existing.email_confirmed_at) {
        await supabaseAdmin.auth.admin.updateUserById(existing.id, { email_confirm: true });
      }
    }

    const { data: authData, error: authError } = await supabasePublic.auth.signInWithPassword({
      email,
      password
    });

    if (authError || !authData.session) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    return res.json({
      ok: true,
      session: authData.session,
      user: authData.user
    });
  } catch (err) {
    return res.status(500).json({ error: "Login failed" });
  }
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
