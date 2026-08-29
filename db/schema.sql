-- ============================================================
-- LinkShield Database Schema (PostgreSQL)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------
-- USERS
-- ------------------------------------------------------------
CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email             VARCHAR(255) UNIQUE NOT NULL,
    phone             VARCHAR(32),
    password_hash     VARCHAR(255) NOT NULL,
    full_name         VARCHAR(255),
    role              VARCHAR(20) NOT NULL DEFAULT 'user', -- user | admin | support
    is_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    avatar_url        TEXT,
    scans_used_this_period INTEGER NOT NULL DEFAULT 0,
    period_reset_at   TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '30 days'),
    last_login_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_email ON users(email);

-- ------------------------------------------------------------
-- SUBSCRIPTIONS (plan catalogue + user assignment)
-- ------------------------------------------------------------
CREATE TABLE subscription_plans (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code          VARCHAR(20) UNIQUE NOT NULL, -- free | plus | family
    name          VARCHAR(50) NOT NULL,
    price_php     NUMERIC(10,2) NOT NULL DEFAULT 0,
    max_members   INTEGER NOT NULL DEFAULT 1,
    scan_limit    INTEGER, -- NULL = unlimited
    features      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id           UUID NOT NULL REFERENCES subscription_plans(id),
    family_owner_id   UUID REFERENCES users(id), -- set for family-member seats
    status            VARCHAR(20) NOT NULL DEFAULT 'active', -- active | canceled | past_due | trialing
    provider          VARCHAR(30), -- e.g. gcash, stripe, paymongo
    provider_ref      VARCHAR(255),
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    current_period_end   TIMESTAMPTZ,
    cancel_at_period_end  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_subscriptions_user ON subscriptions(user_id);

-- ------------------------------------------------------------
-- SCANS (one row per scan request)
-- ------------------------------------------------------------
CREATE TABLE scans (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_type     VARCHAR(20) NOT NULL, -- link | qr | message
    input_raw     TEXT NOT NULL,        -- original URL / decoded QR payload / message text
    source        VARCHAR(30) DEFAULT 'app', -- app | share_extension | api
    origin_app    VARCHAR(30),          -- whatsapp | messenger | sms | telegram | email | browser
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scans_user ON scans(user_id, created_at DESC);
CREATE INDEX idx_scans_type ON scans(scan_type);

-- ------------------------------------------------------------
-- SCAN RESULTS (analysis output for a scan)
-- ------------------------------------------------------------
CREATE TABLE scan_results (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    risk_score        INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level        VARCHAR(10) NOT NULL, -- safe | suspicious | dangerous
    domain            VARCHAR(255),
    final_url         TEXT,               -- after redirect resolution
    redirect_chain    JSONB DEFAULT '[]'::jsonb,
    uses_https        BOOLEAN,
    domain_age_days   INTEGER,
    indicators         JSONB NOT NULL DEFAULT '[]'::jsonb, -- list of {code, label, severity}
    provider_signals  JSONB NOT NULL DEFAULT '{}'::jsonb,  -- raw Safe Browsing / VirusTotal / URLhaus responses (trimmed)
    ai_explanation    TEXT,
    engine_version    VARCHAR(20) DEFAULT 'v1',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scan_results_scan ON scan_results(scan_id);
CREATE INDEX idx_scan_results_level ON scan_results(risk_level);

-- ------------------------------------------------------------
-- THREAT DOMAINS (curated / aggregated known-bad domains)
-- ------------------------------------------------------------
CREATE TABLE threat_domains (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain        VARCHAR(255) UNIQUE NOT NULL,
    category      VARCHAR(30) NOT NULL DEFAULT 'phishing', -- phishing | malware | scam | spam
    severity      VARCHAR(10) NOT NULL DEFAULT 'dangerous',
    source        VARCHAR(30) NOT NULL DEFAULT 'community', -- google_safe_browsing | virustotal | urlhaus | community | admin
    report_count  INTEGER NOT NULL DEFAULT 0,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    notes         TEXT,
    added_by      UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_threat_domains_domain ON threat_domains(domain);

-- ------------------------------------------------------------
-- SCAM REPORTS (user-submitted)
-- ------------------------------------------------------------
CREATE TABLE scam_reports (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    scan_id       UUID REFERENCES scans(id) ON DELETE SET NULL,
    reported_value TEXT NOT NULL, -- URL / domain / message text
    report_type   VARCHAR(20) NOT NULL DEFAULT 'link', -- link | qr | message
    category      VARCHAR(30), -- phishing | fake_reward | impersonation | otp_scam | other
    description   TEXT,
    status        VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending | reviewing | confirmed | rejected
    reviewed_by   UUID REFERENCES users(id),
    reviewed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scam_reports_status ON scam_reports(status);

-- ------------------------------------------------------------
-- NOTIFICATIONS
-- ------------------------------------------------------------
CREATE TABLE notifications (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type          VARCHAR(30) NOT NULL, -- threat_alert | scan_complete | subscription | system
    title         VARCHAR(255) NOT NULL,
    body          TEXT,
    data          JSONB DEFAULT '{}'::jsonb,
    is_read       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_notifications_user ON notifications(user_id, is_read);

-- ------------------------------------------------------------
-- SETTINGS (per-user preferences)
-- ------------------------------------------------------------
CREATE TABLE settings (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme               VARCHAR(10) NOT NULL DEFAULT 'system', -- light | dark | system
    push_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    email_alerts        BOOLEAN NOT NULL DEFAULT TRUE,
    auto_scan_shared_links BOOLEAN NOT NULL DEFAULT TRUE,
    language            VARCHAR(10) NOT NULL DEFAULT 'en',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- AUDIT LOGS (admin + security actions)
-- ------------------------------------------------------------
CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    action        VARCHAR(100) NOT NULL, -- e.g. 'user.login', 'admin.threat_domain.create'
    target_type   VARCHAR(50),
    target_id     VARCHAR(100),
    ip_address    VARCHAR(64),
    user_agent    TEXT,
    metadata       JSONB DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id, created_at DESC);

-- ------------------------------------------------------------
-- MANUAL PAYMENTS (GCash InstaPay proof-of-payment, admin-approved)
-- ------------------------------------------------------------
CREATE TABLE manual_payments (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id         UUID NOT NULL REFERENCES subscription_plans(id),
    method          VARCHAR(30) NOT NULL DEFAULT 'gcash_instapay',
    amount_php      NUMERIC(10,2) NOT NULL,
    reference_number VARCHAR(100), -- GCash reference no. the customer typed in
    proof_image_path VARCHAR(500),  -- uploaded screenshot of the payment
    status          VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    admin_notes     TEXT,
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_manual_payments_user ON manual_payments(user_id, created_at DESC);
CREATE INDEX idx_manual_payments_status ON manual_payments(status, created_at DESC);

-- ------------------------------------------------------------
-- Seed default plans
-- ------------------------------------------------------------
INSERT INTO subscription_plans (code, name, price_php, max_members, scan_limit, features) VALUES
('free',   'Free',   0,   1, 3,    '{"ai_explanations": false, "advanced_analysis": false}'),
('plus',   'Plus',   79,  1, NULL, '{"ai_explanations": true, "advanced_analysis": true}'),
('family', 'Family', 149, 5, NULL, '{"ai_explanations": true, "advanced_analysis": true}')
ON CONFLICT (code) DO NOTHING;
