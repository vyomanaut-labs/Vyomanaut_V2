-- Generated for profile: demo
-- Generated at: 2026-08-29T14:02:18Z
-- ShardSize: 262144 (compile-time constant; NOT profile-variable)
-- DataShards: 3
-- TotalShards: 5

-- ── Extensions ─────────────────────────────────────────────────────────────────
-- btree_gist: required by audit_periods EXCLUDE USING gist (tsrange WITH &&).
-- pgcrypto:   provides gen_random_uuid() for UUID primary-key column defaults.
-- [REF: DM §9, deployments/dev/init-db.sql, CI check-07]
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Roles (ADR-032) ─────────────────────────────────────────────────────────────
-- Role model — three identities with distinct privilege levels:
--   vyomanaut_migrator : OWNS this schema, runs migrations, refreshes materialised
--                        views. Provisioned by the ENVIRONMENT (bootstrap
--                        POSTGRES_USER in dev/CI; DBA-provisioned in prod) — it is
--                        NOT created here, because a migration cannot create the
--                        very role that is running it. MUST hold BYPASSRLS (or be
--                        SUPERUSER) so maintenance and MV refresh can read the
--                        FORCE-RLS tables below.
--   vyomanaut_app      : the microservice request-path role. LOGIN, NOSUPERUSER,
--                        NOBYPASSRLS — fully subject to the Row Security Policies.
--   vyomanaut_gc       : the garbage-collector role. LOGIN, NOSUPERUSER, NOBYPASSRLS.
-- Passwords are set by the deployment (ALTER ROLE ... PASSWORD from a secrets
-- store) — NEVER in this migration. Idempotent: guarded by pg_roles checks, and
-- the defensive ALTERs below re-assert the security-critical attributes even if a
-- role pre-exists from an older migration.
-- [REF: ADR-032, DM §6]
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vyomanaut_app') THEN
        CREATE ROLE vyomanaut_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vyomanaut_gc') THEN
        CREATE ROLE vyomanaut_gc LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END $$;
-- Defensive assertion: abort the migration if either service role was provisioned
-- with RLS-bypassing power. This is READ-ONLY (any role, including a non-superuser
-- migrator, can execute it) and guarantees the append-only policies below cannot be
-- silently defeated by a mis-provisioned role. We assert rather than ALTER because
-- clearing the SUPERUSER attribute itself requires superuser — an assertion keeps
-- the migration runnable by a least-privilege migrator while still failing loudly.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN ('vyomanaut_app', 'vyomanaut_gc')
          AND (rolsuper OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'ADR-032 violation: vyomanaut_app and vyomanaut_gc must be NOSUPERUSER and NOBYPASSRLS (they are subject to the FORCE-RLS append-only policies)';
    END IF;
END $$;

-- ── ENUMs ──────────────────────────────────────────────────────────────────────
-- All nine types below are profile-invariant (identical values in demo and
-- production) and are declared first in the migration, satisfying the DM §9
-- ordering rule: types precede tables.
-- [REF: DM §4, DM §9]

-- provider_status — lifecycle states for a storage provider.
-- PENDING_ONBOARDING : registered, Razorpay cooling period not yet elapsed
-- VETTING            : first heartbeat received; accumulating audit passes
-- ACTIVE             : 80 consecutive passes achieved; full assignment eligibility
-- DEPARTED           : silent (>=72h) or announced departure; never physically deleted
-- [REF: DM §4.2]
CREATE TYPE provider_status AS ENUM (
    'PENDING_ONBOARDING',
    'VETTING',
    'ACTIVE',
    'DEPARTED'
);

-- file_status — lifecycle states for an uploaded file.
-- [REF: DM §4.3, DM §9 three-value checklist]
CREATE TYPE file_status AS ENUM (
    'ACTIVE',
    'DELETION_PENDING',
    'DELETED'
);

-- assignment_status — lifecycle states for a single shard assignment.
-- [REF: DM §4.5]
CREATE TYPE assignment_status AS ENUM (
    'ACTIVE',           -- provider holds this shard; audit challenges issued daily
    'REPAIRING',        -- shard is being replaced; old holder still being challenged
    'PENDING_DELETION', -- owner deleted file (or ACTIVE transition GC in progress);
                        -- provider notified to GC its vLog; no further challenges issued
    'DELETED'           -- provider confirmed deletion; no further challenge issued
);

-- audit_result_type — terminal outcomes of an audit challenge.
-- PASS / FAIL / TIMEOUT are the three terminal states. The column is nullable
-- (no NOT NULL) to represent the in-flight PENDING state during the two-phase
-- write (ADR-015). Defining this as an ENUM, rather than TEXT with a CHECK, is
-- consistent with all other status columns and rejects invalid values at the
-- wire-protocol level before any constraint fires.
-- [REF: DM §4.7]
CREATE TYPE audit_result_type AS ENUM ('PASS', 'FAIL', 'TIMEOUT');

-- escrow_event_type — provider-side escrow ledger event kinds.
-- [REF: DM §4.8; REVERSAL required per DM §9 checklist]
CREATE TYPE escrow_event_type AS ENUM (
    'DEPOSIT',   -- data owner funds escrow; triggers on Razorpay webhook
    'RELEASE',   -- monthly payment released to provider after multiplier applied
    'SEIZURE',   -- all held earnings seized on silent departure (ADR-024)
    'REVERSAL'   -- correction of a previously recorded DEPOSIT/RELEASE/SEIZURE entry
);

-- owner_escrow_event_type — data-owner-side prepaid balance event kinds.
-- [REF: DM §4.9]
CREATE TYPE owner_escrow_event_type AS ENUM (
    'DEPOSIT',      -- data owner funds escrow via UPI Smart Collect 2.0
    'CHARGE',       -- monthly storage deduction per active file (per-audit-pass credits)
    'WITHDRAWAL',   -- owner withdraws available balance to their bank account
    'REFUND'        -- file deleted early; unused prepaid storage refunded
);

-- repair_trigger_type — events that enqueue a repair job.
-- [REF: DM §4.10]
CREATE TYPE repair_trigger_type AS ENUM (
    'SILENT_DEPARTURE',     -- provider absent >=72h; fragments definitely lost
    'ANNOUNCED_DEPARTURE',  -- provider explicitly notified of departure
    'THRESHOLD_WARNING',    -- fragment count dropped to s+r0=24 (lazy threshold)
    'EMERGENCY_FLOOR'       -- fragment count at s=16 (reconstruction floor); immediate
);

-- repair_priority — drain order for the repair job queue.
-- ENUM order = priority order for ORDER BY ASC
-- [REF: DM §4.10, ADR-004]
CREATE TYPE repair_priority AS ENUM (
    'EMERGENCY',            -- EMERGENCY_FLOOR: s=16, immediate, front of queue
    'PERMANENT_DEPARTURE',  -- SILENT or ANNOUNCED departures drain first (ADR-004)
    'PRE_WARNING'           -- THRESHOLD_WARNING jobs wait behind the above
);

-- repair_job_status — lifecycle states for a queued repair job.
-- [REF: DM §4.10]
CREATE TYPE repair_job_status AS ENUM (
    'QUEUED',
    'IN_PROGRESS',
    'COMPLETED',
    'FAILED'
);

-- otp_purpose — which registration/login flow an OTP code gates.
-- [Added, build.md Milestone 11 Phase 11.4] No table for OTP codes existed
-- anywhere in the schema prior to this milestone, despite FR-001 requiring
-- phone-number OTP verification and OAS's OtpSendRequest.purpose already
-- specifying this exact three-value enum.
-- [REF: FR-001, OAS OtpSendRequest.purpose, build.md Phase 11.4]
CREATE TYPE otp_purpose AS ENUM (
    'OWNER_REGISTER',
    'PROVIDER_REGISTER',
    'LOGIN'
);

-- ── owners ─────────────────────────────────────────────────────────────────────
-- [REF: DM §4.1, DM §8.1]
CREATE TABLE owners (
    -- ── Identity ─────────────────────────────────────────────────────────────
    owner_id            UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    -- UUIDv7 preferred at application layer for time-ordered PKs (ADR-013).

    phone_number        VARCHAR(15)     NOT NULL UNIQUE,
    -- E.164 format (e.g. +919876543210). OTP-verified at registration (FR-001).
    -- UNIQUE: one identity per phone number prevents trivial Sybil registration.

    ed25519_public_key  BYTEA           NOT NULL CHECK (octet_length(ed25519_public_key) = 32),
    -- 32-byte compressed Ed25519 public key (ADR-020). Never the private key.

    -- ── Payment ──────────────────────────────────────────────────────────────
    smart_collect_vpa   VARCHAR(255)    NULL,
    -- Razorpay Smart Collect 2.0 virtual UPI payment address.
    -- NULL until Razorpay completes VPA provisioning (DM §8.1).

    -- ── Timestamps ───────────────────────────────────────────────────────────
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE owners IS 'Registered data owners. One row per verified phone number.';
COMMENT ON COLUMN owners.smart_collect_vpa IS
    'Razorpay UPI VPA for escrow deposits. NULL until provisioned by Razorpay webhook.';

-- ── providers ──────────────────────────────────────────────────────────────────
-- [REF: DM §4.2, DM §8.2–§8.6]
CREATE TABLE providers (
    -- ── Identity ─────────────────────────────────────────────────────────────
    provider_id             UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    phone_number            VARCHAR(15)     NOT NULL UNIQUE,
    -- OTP-verified at registration. UNIQUE prevents Sybil attacks (ADR-005).

    ed25519_public_key      BYTEA           NOT NULL CHECK (octet_length(ed25519_public_key) = 32),
    -- libp2p peer key. Authenticates every heartbeat and audit receipt (ADR-021).

    -- ── Lifecycle ────────────────────────────────────────────────────────────
    status                  provider_status NOT NULL DEFAULT 'PENDING_ONBOARDING',

    -- ── Hardware declaration ─────────────────────────────────────────────────
    declared_storage_gb     INT             NOT NULL CHECK (declared_storage_gb BETWEEN 10 AND 100000),
    -- Minimum 10 GB, maximum 100 TB. Verified indirectly by vetting audits (ADR-030).

    city                    VARCHAR(100)    NOT NULL,

    region                  VARCHAR(100)    NOT NULL,
    -- Readiness gate: >=3 distinct metro regions required (ADR-029).

    asn                     VARCHAR(32)     NOT NULL,
    -- e.g. 'AS24560' (Airtel); 'SIM-AS1'...'SIM-AS5' in simulation mode.
    -- 20% ASN cap: no single ASN holds >20% of any file's shards (ADR-014).

    -- ── Payment rails ────────────────────────────────────────────────────────
    razorpay_linked_account_id  VARCHAR(255),
    -- NULL until account.created webhook fires. Assignments blocked until set (DM §8.2).

    razorpay_cooling_until  TIMESTAMPTZ,
    -- NULL until account created; set to NOW() + 24h on webhook receipt (DM §8.3).

    -- ── Network addresses (ADR-028) ──────────────────────────────────────────
    last_known_multiaddrs   JSONB           NOT NULL DEFAULT '[]',
    -- Ordered JSON array of libp2p multiaddrs from the most recent heartbeat.

    last_heartbeat_ts       TIMESTAMPTZ,
    -- NULL during PENDING_ONBOARDING before first heartbeat (DM §8.4).

    multiaddr_stale         BOOLEAN         NOT NULL DEFAULT FALSE,
    -- TRUE when 2+ consecutive heartbeats missed; triggers DHT fallback (ADR-028).

    -- ── Performance counters (ADR-006, ADR-014) ──────────────────────────────
    p95_throughput_kbps     FLOAT           NULL,
    -- NULL until vetting accumulates samples; application substitutes pool median.
    -- DEFAULT 0 is WRONG: causes division by zero in audit deadline formula (ADR-014).

    avg_rtt_ms              FLOAT           NULL,
    -- NULL until first sample; application substitutes pool median.
    -- DEFAULT 2000 is WRONG: hard-coded guess diverges as network median shifts.

    var_rtt_ms              FLOAT           NOT NULL DEFAULT 0,
    -- Zero variance is the correct initial assumption.
    -- RTO = avg_rtt_ms + 4 × var_rtt_ms (ADR-006).

    rto_sample_count        INT             NOT NULL DEFAULT 0,
    -- Below 5: scheduler substitutes pool-median RTO (ADR-006).

    first_chunk_assignment_at   TIMESTAMPTZ,
    -- NULL until first chunk assigned by assignment service (DM §8.6).
    -- Vetting duration check: NOW() - first_chunk_assignment_at >= 120 days (FR-026).

    -- ── Vetting counters (ADR-005) ────────────────────────────────────────────
    consecutive_audit_passes    INT         NOT NULL DEFAULT 0,
    -- 80 consecutive passes → VETTING to ACTIVE transition (Jeffrey's prior, ADR-005).

    -- ── Failure clustering (ADR-008, Paper 32) ───────────────────────────────
    accelerated_reaudit     BOOLEAN         NOT NULL DEFAULT FALSE,
    -- TRUE when >1 FAIL in rolling 7-day window (Paper 32, ADR-008).

    -- ── Escrow freeze (ADR-024) ──────────────────────────────────────────────
    frozen                  BOOLEAN         NOT NULL DEFAULT FALSE,

    -- ── Token refresh rate limiting (build.md Milestone 11 Phase 11.4) ─────────
    last_token_refresh_at   TIMESTAMPTZ,
    -- NULL until the first successful POST /api/v1/provider/token/refresh.
    -- Enforces "one successful refresh per 30 minutes per provider_id" (OAS).

    -- ── Promised downtime (build.md Milestone 11 Phase 11.6 Session 11.6.5) ────
    promised_return_at      TIMESTAMPTZ,
    -- NULL when no downtime window is open. Set by POST /api/v1/provider/downtime
    -- to NOW() + [0, profile.PromisedDowntimeMaximum]; cleared on the next
    -- successful heartbeat or once overrun (FR-032, FR-033, ADR-007). IC §9's own
    -- 'UPDATE promised_return_at' row already assumed this column existed; it did
    -- not, in either data-model.md §4.2 or this file, until this session added it —
    -- the same kind of mid-build schema addition already made for
    -- last_token_refresh_at above.

    -- ── Timestamps ───────────────────────────────────────────────────────────
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    departed_at             TIMESTAMPTZ,
    -- NULL for active providers. Set on departure declaration. Never cleared (DM §8.5).

    -- ── Constraints ──────────────────────────────────────────────────────────
    CONSTRAINT providers_throughput_nonneg  CHECK (p95_throughput_kbps >= 0),
    CONSTRAINT providers_avg_rtt_nonneg     CHECK (avg_rtt_ms >= 0),
    CONSTRAINT providers_var_rtt_nonneg     CHECK (var_rtt_ms >= 0),
    CONSTRAINT providers_passes_nonneg      CHECK (consecutive_audit_passes >= 0),
    CONSTRAINT providers_departed_status
        CHECK (departed_at IS NULL OR status = 'DEPARTED')
);

COMMENT ON TABLE providers IS
    'Storage providers. One row per verified daemon. Never physically deleted (DM §3 Invariant 3).';

-- ── otp_codes ──────────────────────────────────────────────────────────────────
-- [REF: FR-001, OAS OtpSendRequest/OtpSendResponse/OtpVerifyRequest]
CREATE TABLE otp_codes (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    phone_number    VARCHAR(15)     NOT NULL,
    -- E.164 format. Not a foreign key: no owners/providers row may exist yet.

    purpose         otp_purpose     NOT NULL,

    code_hash       BYTEA           NOT NULL CHECK (octet_length(code_hash) = 32),
    -- SHA-256 of the 6-digit code. The plaintext code is never stored.

    expires_at      TIMESTAMPTZ     NOT NULL,
    -- NOW() + 10 minutes at insert time (OAS OtpSendResponse.expires_at).

    consumed_at     TIMESTAMPTZ,
    -- NULL until a successful verify. Sending a second OTP for the same
    -- phone_number/purpose does not consume or delete an earlier row --
    -- only the most recent unconsumed, unexpired one is checked at verify
    -- time. Prevents replaying an already-used code.

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX ON otp_codes (phone_number, purpose, created_at DESC);
-- Supports both the rate-limit check (COUNT WHERE created_at > NOW() - interval)
-- and the verify lookup (most recent unconsumed, unexpired code for this
-- phone_number + purpose).

COMMENT ON TABLE otp_codes IS
    'Ephemeral OTP codes for registration and login (FR-001). Not FK''d to '
    'owners/providers -- an OTP can exist before the entity it gates does. '
    'code_hash only; plaintext is never persisted.';

-- ── pending_registrations ───────────────────────────────────────────────────────
-- [REF: build.md Phase 11.4/11.5 -- bridges a registration token's opaque
-- subject UUID back to the phone number it was issued for]
CREATE TABLE pending_registrations (
    subject         UUID            PRIMARY KEY,
    -- The registration JWT's `sub` claim: UUIDv5(namespace, phone_number).
    -- Not a foreign key -- no owners/providers row exists yet.

    phone_number    VARCHAR(15)     NOT NULL,

    purpose         otp_purpose     NOT NULL,
    -- [M11 audit remediation, Finding 4] The OTP purpose this registration
    -- token was issued under (OWNER_REGISTER or PROVIDER_REGISTER -- LOGIN
    -- never reaches here, since HandleVerify only calls
    -- recordPendingRegistration on the is_new_entity branch). Carried
    -- through so the register endpoint that redeems this row can reject a
    -- token issued for the other role or for LOGIN, per OAS's
    -- OtpSendRequest.purpose description: "The microservice validates that
    -- the subsequent register call matches this declared purpose."
    -- Previously absent entirely -- purpose was checked and stored on
    -- otp_codes at send time but never carried any further, so nothing
    -- downstream of OTP verify could enforce it.

    expires_at      TIMESTAMPTZ     NOT NULL,
    -- Matches the registration token's own TTL (1 hour). A row past this
    -- point is stale; the register endpoint treats it as not found.

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE pending_registrations IS
    'Bridges a registration JWT''s opaque sub claim back to the phone number '
    'and OTP purpose it was issued for. One row per pending registration; '
    'deleted on redemption.';

-- ── files ──────────────────────────────────────────────────────────────────────
-- [REF: DM §4.3, REQ §4.4 FR-019]
CREATE TABLE files (
    -- ── Identity ─────────────────────────────────────────────────────────────
    file_id             UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    -- UUIDv7 at application layer (ADR-013). Pseudonymous: appears in audit
    -- receipts but cannot be linked to plaintext identity without master secret.

    owner_id            UUID            NOT NULL REFERENCES owners(owner_id),

    -- ── Pointer file storage (ADR-020) ───────────────────────────────────────
    pointer_ciphertext  BYTEA           NOT NULL,
    -- AEAD_CHACHA20_POLY1305 ciphertext of the pointer file struct.
    -- Microservice stores blindly; cannot decrypt (ADR-020, zero-knowledge).

    pointer_nonce       BYTEA           NOT NULL CHECK (octet_length(pointer_nonce) = 12),
    -- 96-bit (12-byte) monotone counter nonce. RFC 8439 §2.3.

    pointer_tag         BYTEA           NOT NULL CHECK (octet_length(pointer_tag) = 16),
    -- 16-byte Poly1305 authentication tag. Constant-time verification (NFR-019).

    -- ── File name (nullable) ─────────────────────────────────────────────────
    display_name_ciphertext  BYTEA      NULL,
    -- AEAD_CHACHA20_POLY1305 ciphertext of the user-provided file name.
    -- NULL if owner provides no label (CLI path). Non-null for UI file list (FR-019).
    -- Microservice stores blindly; cannot read the filename (ADR-020).

    display_name_nonce       BYTEA      NULL CHECK (octet_length(display_name_nonce) = 12 OR display_name_nonce IS NULL),

    display_name_tag         BYTEA      NULL CHECK (octet_length(display_name_tag) = 16 OR display_name_tag IS NULL),

    -- ── File metadata ────────────────────────────────────────────────────────
    original_size_bytes BIGINT          NOT NULL CHECK (original_size_bytes > 0),
    -- Plaintext size before padding. Required to strip AONT padding after RS
    -- decode and AONT decryption on retrieval (FR-008).

    status              file_status     NOT NULL DEFAULT 'ACTIVE',

    schema_version      SMALLINT        NOT NULL DEFAULT 1,
    -- Pointer file schema version. Forward-compatible migration for V3.

    -- ── Timestamps ───────────────────────────────────────────────────────────
    uploaded_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE files IS
    'One row per uploaded file. The microservice holds only encrypted pointer '
    'ciphertext and cannot read the file contents or decryption key.';
COMMENT ON COLUMN files.pointer_ciphertext IS
    'Blind store. Key lives in the owner''s head. Service cannot decrypt (ADR-020).';
COMMENT ON COLUMN files.original_size_bytes IS
    'Strip AONT padding to this length after decoding. Padding is added for '
    'files smaller than one full segment (4 MB = 16 × 256 KB).';

-- ── segments ───────────────────────────────────────────────────────────────────
-- [REF: DM §4.4]
CREATE TABLE segments (
    segment_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    file_id         UUID        NOT NULL REFERENCES files(file_id),

    segment_index   INT         NOT NULL CHECK (segment_index >= 0),
    -- 0-based. Segments concatenated in this order on retrieval.

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT segments_unique_index UNIQUE (file_id, segment_index)
    -- A file cannot have two segments at the same position.
);

COMMENT ON TABLE segments IS
    'One row per 14 MB slice of a file. Each segment produces exactly TotalShards chunks '
    'via AONT-RS. Segments are independent: losing one does not affect the others.';

-- ── chunk_assignments ───────────────────────────────────────────────────────────
-- PROFILE-VARIABLE: shard_index upper bound = TotalShards-1 = 4 for this profile.
-- [REF: DM §4.5, DM §3 Invariant 6, DM §8.21, DM §8.22, ADR-030, ADR-031]
CREATE TABLE chunk_assignments (
    assignment_id    UUID                PRIMARY KEY DEFAULT gen_random_uuid(),

    chunk_id         BYTEA               NOT NULL CHECK (octet_length(chunk_id) = 32),
    -- SHA-256(shard_data): content address of this 256 KB shard.
    -- For vetting chunks: SHA-256 of a random 256 KB block (ADR-030).

    is_vetting_chunk BOOLEAN             NOT NULL DEFAULT FALSE,
    -- TRUE for synthetic chunks assigned during provider vetting (ADR-030).
    -- Repair scheduler MUST NOT create repair_jobs for is_vetting_chunk = TRUE.

    segment_id       UUID                REFERENCES segments(segment_id),
    -- NULL when is_vetting_chunk = TRUE (no real file association — DM §8.21).

    shard_index      SMALLINT            CHECK (shard_index BETWEEN 0 AND 4 OR shard_index IS NULL),
    -- NULL when is_vetting_chunk = TRUE (no RS slot — DM §8.22).
    -- Upper bound is profile-variable: TotalShards-1 (ADR-031).

    provider_id      UUID                NOT NULL REFERENCES providers(provider_id),

    status           assignment_status   NOT NULL DEFAULT 'ACTIVE',

    created_at       TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    deleted_at       TIMESTAMPTZ,
    -- NULL for all non-DELETED assignments.

    -- ── Constraints ──────────────────────────────────────────────────────────
    CONSTRAINT chunk_assignments_segment_and_shard_null_iff_vetting CHECK (
        (is_vetting_chunk = FALSE AND segment_id IS NOT NULL AND shard_index IS NOT NULL)
        OR
        (is_vetting_chunk = TRUE  AND segment_id IS NULL    AND shard_index IS NULL)
    ),
    -- Invariant 6: real chunks always reference a segment and shard;
    -- synthetic chunks never do (ADR-030, DM §3 Invariant 6).

    CONSTRAINT chunk_assignments_one_per_provider_per_chunk
        UNIQUE (chunk_id, provider_id)
);

-- Partial unique index: one active assignment per shard slot per segment (real chunks only).
-- Synthetic chunks excluded (no shard_index, no RS constraint applies).
-- MUST be standalone CREATE UNIQUE INDEX, NOT an inline constraint (DM §9).
CREATE UNIQUE INDEX idx_chunk_assignments_one_active_per_shard
    ON chunk_assignments (segment_id, shard_index)
    WHERE is_vetting_chunk = FALSE
      AND status IN ('ACTIVE', 'REPAIRING');

-- Read view: challenge scheduler sees only ACTIVE assignments.
CREATE VIEW active_chunk_assignments AS
SELECT *
FROM chunk_assignments
WHERE status = 'ACTIVE';

COMMENT ON TABLE chunk_assignments IS
    'Routing table: which provider holds which shard of which segment. '
    '20% ASN cap enforced at INSERT time by the assignment service (ADR-014). '
    'Physical deletion not performed; historical data preserved for audit reconciliation.';
COMMENT ON COLUMN chunk_assignments.chunk_id IS
    'SHA-256(shard_data). RocksDB lookup key on the provider daemon (ADR-023).';
COMMENT ON COLUMN chunk_assignments.is_vetting_chunk IS
    'TRUE for synthetic vetting chunks (ADR-030). Repair scheduler must not enqueue '
    'repair jobs for these rows. Provider daemon cannot distinguish synthetic from real.';
COMMENT ON COLUMN chunk_assignments.segment_id IS
    'NULL for synthetic vetting chunks (is_vetting_chunk = TRUE). '
    'Real shards enforced non-null by CHECK constraint (DM §8.21).';
COMMENT ON COLUMN chunk_assignments.shard_index IS
    'NULL for synthetic vetting chunks (no RS shard slot assigned — DM §8.22). '
    'Real shards: 0 to TotalShards-1; 0..DataShards-1 are systematic, rest parity.';

-- ── audit_periods ──────────────────────────────────────────────────────────────
-- PREREQUISITE: CREATE EXTENSION IF NOT EXISTS btree_gist;
-- (already installed above; required by audit_periods_no_overlap EXCLUDE constraint)
-- [REF: DM §4.6]
CREATE TABLE audit_periods (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    provider_id     UUID            NOT NULL REFERENCES providers(provider_id),

    period_start    TIMESTAMPTZ     NOT NULL,
    period_end      TIMESTAMPTZ     NOT NULL,
    -- Inclusive start, exclusive end. One row per calendar month per provider.

    -- ── Running tallies (denormalised from audit_receipts) ────────────────────
    audit_passes    INT             NOT NULL DEFAULT 0 CHECK (audit_passes >= 0),
    audit_fails     INT             NOT NULL DEFAULT 0 CHECK (audit_fails >= 0),
    audit_timeouts  INT             NOT NULL DEFAULT 0 CHECK (audit_timeouts >= 0),
    -- Materialised tallies updated asynchronously after each receipt is countersigned.

    release_computed BOOLEAN        NOT NULL DEFAULT FALSE,
    -- Set TRUE once the monthly release multiplier has been computed (ADR-024).

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT audit_periods_no_overlap
        -- PREREQUISITE: CREATE EXTENSION IF NOT EXISTS btree_gist;
        EXCLUDE USING gist (
            provider_id WITH =,
            tstzrange(period_start, period_end, '[)') WITH &&
        ),
    -- Two audit periods for the same provider must not overlap.
    -- Requires btree_gist. Prevents double-counting at month boundaries (ADR-016).

    CONSTRAINT audit_periods_start_before_end
        CHECK (period_start < period_end)
);

COMMENT ON TABLE audit_periods IS
    'One row per calendar month per provider. Denormalised tally for scoring '
    'and release computation. Source of truth for the escrow release multiplier.';

-- ── audit_receipts ─────────────────────────────────────────────────────────────
-- [REF: DM §4.7, DM §3 Invariants 1 and 5, DM §8.9–§8.15, DM §8.20]
-- INSERT only (Invariant 1). The only UPDATE promotes PENDING → final state.
-- No DELETE ever.
CREATE TABLE audit_receipts (
    -- ── Primary key ──────────────────────────────────────────────────────────
    -- Partitioned by RANGE (server_challenge_ts) — see PARTITION BY clause and
    -- ADR-033. Postgres requires the partition key in every UNIQUE/PK constraint,
    -- so the primary key is the composite (receipt_id, server_challenge_ts),
    -- declared in the constraints block below (not inline here).
    receipt_id              UUID            NOT NULL DEFAULT gen_random_uuid(),

    schema_version          SMALLINT        NOT NULL DEFAULT 1,

    -- ── What was challenged ──────────────────────────────────────────────────
    chunk_id                BYTEA           NOT NULL CHECK (octet_length(chunk_id) = 32),

    file_id                 UUID            REFERENCES files(file_id),
    -- NULL for synthetic vetting chunk audits (DM §8.20, ADR-030).
    -- Non-null for all real shard audits.

    provider_id             UUID            NOT NULL REFERENCES providers(provider_id),

    -- ── Challenge parameters (ADR-017, ADR-027) ──────────────────────────────
    challenge_nonce         BYTEA           NOT NULL CHECK (octet_length(challenge_nonce) = 33),
    -- MUST BE 33 BYTES, NOT 32. 1-byte version || HMAC-SHA256(server_secret_vN,
    -- chunk_id || server_ts). Version byte enables cross-replica validation
    -- after failover (ADR-027, DM §3 Invariant 5, CI check-08).

    server_challenge_ts     TIMESTAMPTZ     NOT NULL,

    -- ── Provider response ────────────────────────────────────────────────────
    response_hash           BYTEA           CHECK (octet_length(response_hash) = 32
                                                OR response_hash IS NULL),
    -- NULL for TIMEOUT (no response) or PENDING (in-flight). See DM §8.9.

    response_latency_ms     INT             CHECK (response_latency_ms >= 0
                                                OR response_latency_ms IS NULL),
    -- NULL for TIMEOUT or PENDING. See DM §8.10.

    -- ── Audit result (two-phase write, ADR-015) ──────────────────────────────
    audit_result            audit_result_type,
    -- NULL = PENDING (in-flight, Phase 1 complete; Phase 2 not yet executed).
    -- PASS / FAIL / TIMEOUT = final result set in Phase 2.
    -- NO DEFAULT. NULL is the intended initial state. (DM §9 checklist)

    address_was_stale       BOOLEAN         NOT NULL DEFAULT FALSE,
    -- TRUE if challenge dispatched via DHT fallback (multiaddr_stale = TRUE).
    -- TIMEOUTs with this flag set do NOT reset consecutive_audit_passes (ADR-028).

    -- ── Signatures (dual Ed25519, ADR-017) ───────────────────────────────────
    provider_sig            BYTEA           CHECK (octet_length(provider_sig) = 64
                                                OR provider_sig IS NULL),
    -- NULL for TIMEOUT or PENDING. See DM §8.12.

    service_sig             BYTEA           CHECK (octet_length(service_sig) = 64
                                                OR service_sig IS NULL),
    -- NULL during PENDING. Non-null for TIMEOUT rows (microservice signs TIMEOUT).
    -- See DM §8.13.

    service_countersign_ts  TIMESTAMPTZ,
    -- NULL during PENDING. Set in Phase 2 alongside service_sig. See DM §8.14.

    -- ── Adversarial detection (ADR-014) ─────────────────────────────────────
    jit_flag                BOOLEAN         NOT NULL DEFAULT FALSE,
    -- TRUE when response_latency_ms is anomalously fast (JIT retrieval, ADR-014).

    -- ── Garbage collection (ADR-015) ────────────────────────────────────────
    abandoned_at            TIMESTAMPTZ,
    -- Set by GC on PENDING rows older than 48 hours. See DM §8.15.

    -- ── Constraints ──────────────────────────────────────────────────────────
    CONSTRAINT audit_receipts_pkey
        PRIMARY KEY (receipt_id, server_challenge_ts),
    -- Composite PK: partition key (server_challenge_ts) MUST be part of the PK on
    -- a partitioned table (ADR-033). receipt_id remains globally unique in practice
    -- (gen_random_uuid); the ts is appended only to satisfy the partition rule.

    CONSTRAINT audit_receipts_nonce_unique
        UNIQUE (challenge_nonce, server_challenge_ts),
    -- LOCAL (per-partition) uniqueness. GLOBAL nonce uniqueness — the actual replay
    -- guarantee (DM §3 Invariant 5) — is enforced by the non-partitioned
    -- audit_receipt_nonces guard table below, which a partitioned table cannot
    -- enforce on challenge_nonce alone (ADR-033).

    CONSTRAINT audit_receipts_response_consistency CHECK (
        (audit_result IN ('PASS', 'FAIL') AND response_hash IS NOT NULL AND provider_sig IS NOT NULL)
        OR
        (audit_result = 'TIMEOUT' AND response_hash IS NULL AND provider_sig IS NULL)
        OR
        (audit_result IS NULL)
    ),

    CONSTRAINT audit_receipts_service_sig_consistency CHECK (
        (service_sig IS NULL) = (service_countersign_ts IS NULL)
    )
    -- No FK to chunk_assignments: chunk_assignments may be soft-deleted while
    -- audit_receipts must remain permanently (Invariant 1).
) PARTITION BY RANGE (server_challenge_ts);
-- ADR-033: monthly RANGE partitioning. This is the mechanism that lets the
-- append-only audit log be archived without a DML DELETE — old months are
-- DETACHed (DDL), never row-deleted (which Invariant 1 forbids). Satisfies the
-- DM §9 "partition from day one" mandate and the ADR-015 "periodic archival"
-- trade-off (architecture.md §25).

-- DEFAULT partition: at V2 scale (architecture.md §26: hundreds of providers, far
-- below the audit ceiling) all rows land here and the table "just works". When
-- volume grows, create monthly partitions AHEAD of time with
-- vyomanaut_create_audit_receipts_partition() below, then DETACH old months to
-- cold storage. Emitting a DEFAULT partition (rather than a NOW()-based monthly
-- partition) keeps this migration deterministic. (ADR-033)
CREATE TABLE audit_receipts_default PARTITION OF audit_receipts DEFAULT;

-- ── audit_receipt_nonces — GLOBAL nonce-uniqueness guard (Invariant 5) ─────────
-- A partitioned table cannot enforce global uniqueness on challenge_nonce alone
-- (the unique key must include the partition key). This small, non-partitioned
-- table holds the global replay-protection guarantee: the microservice INSERTs the
-- nonce here in the SAME TRANSACTION as the receipt (IC §6, ADR-033). A duplicate
-- nonce raises a PK violation and aborts the audit write — the replay is rejected.
-- Retention is bounded: rows older than the challenge-validity / secret-rotation
-- window may be pruned by the migrator, keeping this index small even at V3 scale
-- (capacity.md). Pruning here is safe — an expired nonce can never be replayed.
CREATE TABLE audit_receipt_nonces (
    challenge_nonce      BYTEA        PRIMARY KEY CHECK (octet_length(challenge_nonce) = 33),
    server_challenge_ts  TIMESTAMPTZ  NOT NULL
);
COMMENT ON TABLE audit_receipt_nonces IS
    'Global replay-protection guard for audit_receipts (DM §3 Invariant 5, ADR-033). '
    'One row per challenge_nonce, written in the same txn as the receipt. Prunable by '
    'server_challenge_ts once the challenge-validity window has passed.';

-- ── Partition maintenance (ADR-033) ───────────────────────────────────────────
-- Deterministic DDL helper: creates the monthly partition covering p_month. A
-- scheduled maintenance job calls this for next month BEFORE its rows arrive, e.g.
--   SELECT vyomanaut_create_audit_receipts_partition((date_trunc('month', now()) + interval '1 month')::date);
-- Archival (once a month is closed and exported to cold storage):
--   ALTER TABLE audit_receipts DETACH PARTITION audit_receipts_2026_01;  -- DDL, not DELETE
-- We deliberately do NOT depend on pg_partman: it is a non-trusted extension and
-- architecture.md §25.1 forbids re-introducing a rejected dependency without an ADR.
CREATE OR REPLACE FUNCTION vyomanaut_create_audit_receipts_partition(p_month DATE)
    RETURNS void
    LANGUAGE plpgsql
AS $$
DECLARE
    v_start DATE := date_trunc('month', p_month)::date;
    v_end   DATE := (date_trunc('month', p_month) + INTERVAL '1 month')::date;
    v_name  TEXT := format('audit_receipts_%s', to_char(v_start, 'YYYY_MM'));
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_receipts FOR VALUES FROM (%L) TO (%L)',
        v_name, v_start, v_end
    );
END;
$$;

-- Nightly data integrity check — must return 0:
-- SELECT COUNT(*) FROM audit_receipts ar
--   JOIN chunk_assignments ca ON ca.chunk_id = ar.chunk_id
--     AND ca.provider_id = ar.provider_id
--   WHERE ar.file_id IS NULL AND ca.is_vetting_chunk = FALSE;

COMMENT ON TABLE audit_receipts IS
    'Immutable audit log. Every storage proof event: PASS, FAIL, TIMEOUT, or '
    'in-flight PENDING. INSERT only — the only permitted UPDATE promotes a '
    'PENDING row to its final state. No DELETE ever. (ADR-015, NFR-021)';
COMMENT ON COLUMN audit_receipts.challenge_nonce IS
    'BYTEA(33): 1-byte version || 32-byte HMAC. NOT BYTEA(32). '
    'Version byte enables cross-replica validation after failover (ADR-027).';
COMMENT ON COLUMN audit_receipts.audit_result IS
    'NULL = PENDING (in-flight, Phase 1 complete). '
    'PASS/FAIL/TIMEOUT = final state set in Phase 2. '
    'NULL is a meaningful state, not a missing value.';

-- ── escrow_events ──────────────────────────────────────────────────────────────
-- [REF: DM §4.8, DM §3 Invariants 2 and 4, DM §8.16]
-- INSERT only (Invariant 2). No UPDATE. No DELETE.
CREATE TABLE escrow_events (
    event_id            UUID                PRIMARY KEY DEFAULT gen_random_uuid(),

    provider_id         UUID                NOT NULL REFERENCES providers(provider_id),

    event_type          escrow_event_type   NOT NULL,
    -- Includes REVERSAL (DM §9 checklist, DM §7 mv_provider_escrow_balance).

    amount_paise        BIGINT              NOT NULL CHECK (amount_paise > 0),
    -- BIGINT ONLY. No FLOAT, NUMERIC, DECIMAL anywhere in the payment path.
    -- Sign implied by event_type: DEPOSIT/REVERSAL adds; RELEASE/SEIZURE subtracts.
    -- RS1 = 100 paise (ADR-016, Invariant 4, NFR-046).

    audit_period_id     UUID                REFERENCES audit_periods(id),
    -- NULL for DEPOSIT (triggered by owner UPI payment) and SEIZURE
    -- (full balance seized at departure). Non-null for RELEASE. See DM §8.16.

    idempotency_key     VARCHAR(64)         NOT NULL UNIQUE,
    -- Prevents double-payment. Passed to Razorpay as X-Payout-Idempotency.
    -- RELEASE:  SHA-256(provider_id || audit_period) as 64 hex chars.
    -- REVERSAL: SHA-256('reversal' || original_idempotency_key).

    created_at          TIMESTAMPTZ         NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE escrow_events IS
    'Append-only escrow ledger. Balance = SUM(DEPOSIT) - SUM(RELEASE + SEIZURE + REVERSAL) '
    'per provider_id. No UPDATE. No DELETE. All amounts in integer paise (ADR-016, Invariant 2).';
COMMENT ON COLUMN escrow_events.amount_paise IS
    'Integer paise ONLY. BIGINT. No FLOAT. RS1 = 100 paise (NFR-046).';

-- ── owner_escrow_events ─────────────────────────────────────────────────────────
-- [REF: DM §4.9, FR-014, FR-021, FR-059]
-- Required for: FR-014 (balance check before upload), FR-021 (balance view),
-- FR-059 (withdrawal). INSERT only. No UPDATE. No DELETE.
CREATE TABLE owner_escrow_events (
    event_id            UUID                        PRIMARY KEY DEFAULT gen_random_uuid(),

    owner_id            UUID                        NOT NULL REFERENCES owners(owner_id),

    event_type          owner_escrow_event_type     NOT NULL,

    amount_paise        BIGINT                      NOT NULL CHECK (amount_paise > 0),
    -- BIGINT ONLY. No FLOAT, NUMERIC, DECIMAL. RS1 = 100 paise (Invariant 4).

    file_id             UUID                        REFERENCES files(file_id),
    -- Non-null for CHARGE and REFUND (links to the specific file).
    -- NULL for DEPOSIT and WITHDRAWAL.

    idempotency_key     VARCHAR(64)                 NOT NULL UNIQUE,
    -- SHA-256(owner_id || razorpay_webhook_id) for DEPOSIT.
    -- SHA-256(owner_id || file_id || billing_period) for CHARGE.

    created_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW()
);

-- Balance query (used by mv_owner_escrow_balance and FR-021 endpoint):
-- SUM(DEPOSIT) - SUM(CHARGE + WITHDRAWAL) + SUM(REFUND) per owner_id

COMMENT ON TABLE owner_escrow_events IS
    'Append-only owner prepaid balance ledger. '
    'Balance = SUM(DEPOSIT + REFUND) - SUM(CHARGE + WITHDRAWAL) per owner_id. '
    'No UPDATE. No DELETE. All amounts in integer paise (Invariant 4). '
    'Required for FR-014, FR-021, FR-059.';
COMMENT ON COLUMN owner_escrow_events.amount_paise IS
    'Integer paise ONLY. BIGINT. No FLOAT. RS1 = 100 paise (NFR-046).';

-- ── repair_jobs ─────────────────────────────────────────────────────────────────
-- PROFILE-VARIABLE: available_shard_count range = [3, 5] for this profile.
-- [REF: DM §4.10, DM §8.17–§8.19, IC §5.7, ADR-004, ADR-031]
-- Departure-trigger deduplication is at application layer (IC §5.7).
CREATE TABLE repair_jobs (
    job_id                  UUID                PRIMARY KEY DEFAULT gen_random_uuid(),

    chunk_id                BYTEA               NOT NULL CHECK (octet_length(chunk_id) = 32),
    -- Content address of the chunk needing repair.

    segment_id              UUID                NOT NULL REFERENCES segments(segment_id),

    provider_id             UUID                REFERENCES providers(provider_id),
    -- NULL for THRESHOLD_WARNING / EMERGENCY_FLOOR triggers (DM §8.17).
    -- No single departure caused the drop; count drifted below threshold.

    trigger_type            repair_trigger_type NOT NULL,

    priority                repair_priority     NOT NULL,

    status                  repair_job_status   NOT NULL DEFAULT 'QUEUED',

    available_shard_count   SMALLINT            NOT NULL
                            CHECK (available_shard_count BETWEEN 3 AND 5),
    -- PROFILE-VARIABLE bounds (generator.go, ADR-031).
    -- prod: [16, 56]  demo: [3, 5]

    created_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    started_at              TIMESTAMPTZ,
    -- NULL until a repair worker picks up the job (DM §8.18).

    completed_at            TIMESTAMPTZ,
    -- NULL until the job reaches COMPLETED or FAILED (DM §8.19).

    failure_reason          TEXT,
    -- [Added, live verification, M17-E Phase 17.7] NULL unless status =
    -- 'FAILED'. The wrapped Go error text MarkJobComplete's caller
    -- (internal/repair/executor.go, every ExecuteRepairJob failure
    -- branch) was already producing on every failure path anyway, now
    -- persisted here instead of only ever reaching a transient
    -- log.Printf line (cmd/microservice/repair_loop.go) that repeated
    -- live-verification sessions found missing or truncated by the
    -- time it needed reading. Deliberately unconstrained TEXT, not an
    -- enum: these are free-form fmt.Errorf chains, not a fixed
    -- vocabulary.

    -- ── Constraints ──────────────────────────────────────────────────────────
    CONSTRAINT repair_jobs_priority_matches_trigger CHECK (
        (trigger_type = 'EMERGENCY_FLOOR' AND priority = 'EMERGENCY')
        OR
        (trigger_type IN ('SILENT_DEPARTURE', 'ANNOUNCED_DEPARTURE')
                AND priority = 'PERMANENT_DEPARTURE')
        OR
        (trigger_type = 'THRESHOLD_WARNING' AND priority IN ('PRE_WARNING', 'PERMANENT_DEPARTURE'))
    ),
    -- Priority derived from trigger_type; prevents drift at application layer.
    -- THRESHOLD_WARNING is the one trigger_type with two legal priority
    -- values: PRE_WARNING at creation, promoted to PERMANENT_DEPARTURE by
    -- PromoteStalePreWarningJobs once RepairPromotionTimeout elapses
    -- unserviced (FR-043, IC §5.7, build.md Phase 9.2 Session 9.2.2). Fixed
    -- here from the original single-value pairing, which made that
    -- promotion — an explicit functional requirement — impossible to
    -- satisfy: no UPDATE could ever set priority = PERMANENT_DEPARTURE on a
    -- row whose trigger_type stays THRESHOLD_WARNING without violating this
    -- very constraint. EMERGENCY_FLOOR and SILENT/ANNOUNCED_DEPARTURE are
    -- unaffected: only threshold-triggered jobs are ever promoted.

    CONSTRAINT repair_jobs_completed_after_started CHECK (
        completed_at IS NULL OR started_at IS NOT NULL
    )
    -- Departure-trigger deduplication is at application layer (IC §5.7).
    -- UNIQUE (chunk_id, provider_id, trigger_type) was removed; see build.md §4.4.5.
);

-- Partial unique index for threshold deduplication (DM §5, IC §5.7).
-- Prevents multiple QUEUED/IN_PROGRESS threshold jobs for the same chunk.
CREATE UNIQUE INDEX idx_repair_jobs_threshold_no_dup
    ON repair_jobs (chunk_id, trigger_type)
    WHERE provider_id IS NULL AND status IN ('QUEUED', 'IN_PROGRESS');

COMMENT ON TABLE repair_jobs IS
    'Repair queue. Priority ordering: EMERGENCY first, then PERMANENT_DEPARTURE, '
    'then PRE_WARNING (ADR-004, Paper 39). FIFO within each priority tier.';
COMMENT ON COLUMN repair_jobs.provider_id IS
    'NULL for threshold-triggered repairs (THRESHOLD_WARNING, EMERGENCY_FLOOR) '
    'where no single departure caused the drop. Non-null for departure-triggered.';
COMMENT ON COLUMN repair_jobs.available_shard_count IS
    'Shard count at job creation. Profile-variable CHECK bounds: '
    'prod=[16,56], demo=[3,5] (generated by generator.go, ADR-031).';

-- ── Indexes ─────────────────────────────────────────────────────────────────────
-- Profile-invariant. All CREATE INDEX statements appear after all CREATE TABLE
-- statements (DM §9 ordering rule). Two exceptions created inline with their tables:
--   idx_chunk_assignments_one_active_per_shard (Session 4.3.5)
--   idx_repair_jobs_threshold_no_dup           (Session 4.4.5)
-- [REF: DM §5, build.md Phase 4.5 Session 4.5.1]

-- ── owners ─────────────────────────────────────────────────────────────────────

-- Query: lookup by phone at login / OTP verification
CREATE UNIQUE INDEX idx_owners_phone ON owners (phone_number);

-- ── providers ───────────────────────────────────────────────────────────────────

-- Query: departure detector — find providers with last_heartbeat_ts > 72h ago
CREATE INDEX idx_providers_heartbeat_active ON providers (last_heartbeat_ts)
    WHERE status = 'ACTIVE';

-- Query: assignment service — select ACTIVE providers for ASN cap check
CREATE INDEX idx_providers_asn_active ON providers (asn) WHERE status = 'ACTIVE';

-- Query: readiness gate — count providers by status AND region
CREATE INDEX idx_providers_status_region ON providers (status, region);

-- Query: lookup by phone at registration / OTP re-verification
CREATE UNIQUE INDEX idx_providers_phone ON providers (phone_number);

-- ── files ───────────────────────────────────────────────────────────────────────

-- Query: file list for a data owner dashboard
CREATE INDEX idx_files_owner ON files (owner_id, uploaded_at DESC)
    WHERE status = 'ACTIVE';

-- Query: find files awaiting deletion confirmation for the GC retry loop (FR-020)
CREATE INDEX idx_files_pending_deletion ON files (owner_id, uploaded_at)
    WHERE status = 'DELETION_PENDING';

-- ── segments ─────────────────────────────────────────────────────────────────────

-- Query: fetch all segments for a file in order (upload orchestrator, retrieval)
CREATE INDEX idx_segments_file ON segments (file_id, segment_index);

-- ── chunk_assignments ────────────────────────────────────────────────────────────

-- Query: challenge scheduler — find all active chunks for a provider
CREATE INDEX idx_chunk_assignments_provider_active ON chunk_assignments (provider_id)
    WHERE status = 'ACTIVE';

-- Query: repair scheduler — find surviving shard holders for a segment
CREATE INDEX idx_chunk_assignments_segment_active ON chunk_assignments (segment_id)
    WHERE status IN ('ACTIVE', 'REPAIRING');

-- Query: deletion workflow — find pending deletions per provider for GC
CREATE INDEX idx_chunk_assignments_provider_pending_deletion
    ON chunk_assignments (provider_id) WHERE status = 'PENDING_DELETION';

-- Query: ASN cap check at assignment time — shards per segment per provider
CREATE INDEX idx_chunk_assignments_segment_provider
    ON chunk_assignments (segment_id, provider_id) WHERE status = 'ACTIVE';

-- Query: ACTIVE transition GC — fetch synthetic chunk IDs to send to daemon
CREATE INDEX idx_chunk_assignments_vetting_provider_active
    ON chunk_assignments (provider_id)
    WHERE is_vetting_chunk = TRUE AND status = 'ACTIVE';

-- Query: departure handler — bulk soft-delete synthetic chunks on vetting departure
CREATE INDEX idx_chunk_assignments_vetting_provider
    ON chunk_assignments (provider_id) WHERE is_vetting_chunk = TRUE;

-- ── audit_periods ────────────────────────────────────────────────────────────────

-- Query: monthly release computation — get current period per provider
CREATE INDEX idx_audit_periods_provider_recent
    ON audit_periods (provider_id, period_start DESC);

-- Query: scoring queries (three-window score: 24h, 7d, 30d)
CREATE INDEX idx_audit_periods_provider_range
    ON audit_periods (provider_id, period_start, period_end);

-- ── audit_receipts ───────────────────────────────────────────────────────────────

-- Query: three-window scoring — sum PASS/FAIL/TIMEOUT for a provider in a window
CREATE INDEX idx_audit_receipts_provider_ts
    ON audit_receipts (provider_id, server_challenge_ts DESC)
    WHERE abandoned_at IS NULL AND audit_result IS NOT NULL;

-- NOTE: UNIQUE on challenge_nonce already created as table constraint
-- (audit_receipts_nonce_unique); no extra index for nonce idempotency lookups.

-- Query: GC process — find PENDING rows older than 48h for abandonment
CREATE INDEX idx_audit_receipts_pending_stale
    ON audit_receipts (server_challenge_ts)
    WHERE audit_result IS NULL AND abandoned_at IS NULL;

-- Query: JIT analysis — count jit_flags per provider in a rolling 7-day window
CREATE INDEX idx_audit_receipts_jit_provider
    ON audit_receipts (provider_id, server_challenge_ts DESC) WHERE jit_flag = TRUE;

-- Query: dispute resolution — provider retrieves their own receipts (FR-058)
CREATE INDEX idx_audit_receipts_provider_file
    ON audit_receipts (provider_id, file_id, server_challenge_ts DESC);

-- Query: FR-058 provider dispute evidence — filter receipts by chunk_id
CREATE INDEX idx_audit_receipts_provider_chunk
    ON audit_receipts (provider_id, chunk_id, server_challenge_ts DESC);

-- ── escrow_events ────────────────────────────────────────────────────────────────

-- Query: balance computation — SUM(DEPOSIT) - SUM(RELEASE + SEIZURE) per provider
CREATE INDEX idx_escrow_events_provider ON escrow_events (provider_id, event_type);

-- Query: monthly release job — join with audit_periods to mark release_computed
CREATE INDEX idx_escrow_events_period ON escrow_events (audit_period_id)
    WHERE audit_period_id IS NOT NULL;

-- ── repair_jobs ──────────────────────────────────────────────────────────────────

-- Query: repair scheduler main dequeue — next queued job by priority then created_at
CREATE INDEX idx_repair_jobs_queue ON repair_jobs (priority, created_at ASC)
    WHERE status = 'QUEUED';

-- Query: repair dashboard — current depth of each priority tier
CREATE INDEX idx_repair_jobs_status_priority ON repair_jobs (status, priority);

-- Query: link repair jobs to a departing provider's chunks
CREATE INDEX idx_repair_jobs_provider ON repair_jobs (provider_id)
    WHERE provider_id IS NOT NULL;

-- (idx_repair_jobs_threshold_no_dup created inline with repair_jobs — exception)

-- ── Row Security Policies ─────────────────────────────────────────────────────
-- Enforces DM §3 Invariants 1–3 at the database engine level, independent of
-- application code. Profile-invariant: identical in demo and production.
-- [REF: DM §6, IC §6, build.md Phase 4.6]

-- ── audit_receipts — INSERT only (Invariant 1) ────────────────────────────────
-- [REF: DM §6, DM §3 Invariant 1, ADR-015, ADR-032, build.md Phase 4.6 Session 4.6.1]
ALTER TABLE audit_receipts ENABLE ROW LEVEL SECURITY;
-- FORCE so the policies apply even to a role that OWNS the table. Without this,
-- an owner (or superuser) silently bypasses append-only enforcement (ADR-032).
ALTER TABLE audit_receipts FORCE  ROW LEVEL SECURITY;

-- SELECT: the request path must read receipts (own-receipt lookups, and the row
-- read that the two-phase UPDATE's WHERE clause performs under FORCE RLS — without
-- a SELECT policy that UPDATE silently matches zero rows). (ADR-032)
CREATE POLICY audit_receipts_app_select
    ON audit_receipts
    FOR SELECT
    TO vyomanaut_app
    USING (TRUE);

-- Phase 1 of the two-phase write: the microservice inserts a PENDING receipt
-- (audit_result = NULL) immediately after dispatching the challenge.
CREATE POLICY audit_receipts_insert_only
    ON audit_receipts
    FOR INSERT
    TO vyomanaut_app
    WITH CHECK (TRUE);

-- Phase 2 of the two-phase write: promotes a PENDING row to its terminal
-- state. This is the ONLY permitted UPDATE on audit_receipts that sets a
-- terminal audit_result. Scope is narrowly limited: only audit_result,
-- service_sig, and service_countersign_ts may be written; all other fields
-- are immutable once the Phase 1 INSERT completes.
CREATE POLICY audit_receipts_phase2_update
    ON audit_receipts
    FOR UPDATE
    TO vyomanaut_app
    USING (audit_result IS NULL AND abandoned_at IS NULL)
    WITH CHECK (
        audit_result   IN ('PASS', 'FAIL', 'TIMEOUT') AND
        service_sig    IS NOT NULL AND
        service_countersign_ts IS NOT NULL
    );

-- Milestone 7 corrections session (Option B, three-phase write): persists
-- response_hash, provider_sig, response_latency_ms, and jit_flag onto a
-- still-PENDING row the instant a provider's signed response is validated —
-- BEFORE audit_receipts_phase2_update above adjudicates PASS/FAIL/TIMEOUT.
-- This is a SEPARATE PERMISSIVE policy, not an edit to
-- audit_receipts_phase2_update above: PostgreSQL ORs the USING/WITH CHECK
-- clauses of multiple PERMISSIVE policies for the same role and command, so
-- the two policies together cover exactly the two UPDATE shapes vyomanaut_app
-- performs on this table — audit_result staying NULL (this policy) or
-- becoming terminal (the policy above) — and nothing else. WITH CHECK below
-- requires audit_result to REMAIN NULL specifically so this policy can never
-- be (ab)used to set a terminal result without going through the policy
-- above.
CREATE POLICY audit_receipts_record_response
    ON audit_receipts
    FOR UPDATE
    TO vyomanaut_app
    USING (
        audit_result IS NULL AND
        abandoned_at IS NULL AND
        response_hash IS NULL
    )
    WITH CHECK (
        audit_result   IS NULL AND
        response_hash  IS NOT NULL AND
        provider_sig   IS NOT NULL
    );

-- Allow the GC process to mark stale PENDING rows as abandoned after 48h,
-- without ever setting a terminal audit_result.
CREATE POLICY audit_receipts_gc_abandon
    ON audit_receipts
    FOR UPDATE
    TO vyomanaut_gc
    USING (
        audit_result IS NULL AND
        abandoned_at IS NULL AND
        server_challenge_ts < NOW() - INTERVAL '48 hours'
        -- NOTE: This RSP hardcodes 48 hours at the DB layer.
        -- The application-layer GC query uses `profile.PendingReceiptGCAge` (demo=5min, prod=48h).
        -- These are SEPARATE mechanisms:
        --   RSP: enforces the maximum DB-level update window (always 48h)
        --   App query: fires early in demo mode using `profile.PendingReceiptGCAge`
        -- The RSP is a safety backstop; the app fires first in demo.
    )
    WITH CHECK (
        abandoned_at IS NOT NULL AND
        audit_result IS NULL      -- GC never sets the result; only abandoned_at
    );

-- SELECT for the GC role: the abandon UPDATE's USING/WHERE clause must be able to
-- read the stale PENDING rows it targets under FORCE RLS. (ADR-032)
CREATE POLICY audit_receipts_gc_select
    ON audit_receipts
    FOR SELECT
    TO vyomanaut_gc
    USING (TRUE);

-- No DELETE policy is created. Any DELETE attempt — by any role — returns
-- permission denied. No physical deletion is ever permitted (Invariant 1).

-- ── escrow_events — INSERT only (Invariant 2) ─────────────────────────────────
-- [REF: DM §6, DM §3 Invariant 2, ADR-016, ADR-032, build.md Phase 4.6 Session 4.6.2]
ALTER TABLE escrow_events ENABLE ROW LEVEL SECURITY;
-- FORCE so append-only holds even for a table owner (ADR-032).
ALTER TABLE escrow_events FORCE  ROW LEVEL SECURITY;

-- SELECT: the request path reads the ledger for idempotency-key checks and any
-- direct balance queries that do not go through the materialised view. (ADR-032)
CREATE POLICY escrow_events_app_select
    ON escrow_events
    FOR SELECT
    TO vyomanaut_app
    USING (TRUE);

CREATE POLICY escrow_events_insert_only
    ON escrow_events
    FOR INSERT
    TO vyomanaut_app
    WITH CHECK (TRUE);

-- No UPDATE or DELETE policy. Balance is always recomputed from the
-- immutable event log; there is no mutable balance column to protect.
-- Any UPDATE or DELETE attempt — by any role — returns permission denied
-- (Invariant 2).

-- ── chunk_assignments — soft-delete only ──────────────────────────────────────
-- Historical incident: a HARD-DELETE was previously issued against this
-- table when a provider underwent a SILENT/ANNOUNCED departure. This is the
-- corrective control: physical deletion is never permitted again, for any
-- role. The only way to retire a row is the existing soft-delete pattern
-- (UPDATE status = 'DELETED', deleted_at = NOW()) — see IC §6.
-- [REF: DM §6, IC §6, ADR-007, ADR-032, build.md Phase 4.6 Session 4.6.3]
ALTER TABLE chunk_assignments ENABLE ROW LEVEL SECURITY;
-- FORCE so soft-delete-only holds even for a table owner (ADR-032).
ALTER TABLE chunk_assignments FORCE  ROW LEVEL SECURITY;

-- SELECT: the request path reads assignments constantly (assignment lookups,
-- repair scheduling, dashboard) and the status UPDATE's WHERE clause must read
-- the target row under FORCE RLS. (ADR-032)
CREATE POLICY chunk_assignments_app_select
    ON chunk_assignments
    FOR SELECT
    TO vyomanaut_app
    USING (TRUE);

-- Normal assignment creation: upload assignment and repair replacement.
-- The is_vetting_chunk / segment_id / shard_index consistency contract
-- (providers.status = 'VETTING' implies is_vetting_chunk = TRUE with NULL
-- segment_id/shard_index, and vice versa for 'ACTIVE') is the application's
-- responsibility (IC §6); the CHECK constraint
-- chunk_assignments_segment_and_shard_null_iff_vetting is a backstop, not
-- the primary guard.
CREATE POLICY chunk_assignments_insert_only
    ON chunk_assignments
    FOR INSERT
    TO vyomanaut_app
    WITH CHECK (TRUE);

-- All status lifecycle transitions, including the departure-handler
-- soft-delete. A row transitioning to DELETED must carry a deleted_at
-- timestamp: this is the soft-delete contract that replaces the historical
-- hard DELETE referenced above.
CREATE POLICY chunk_assignments_status_update
    ON chunk_assignments
    FOR UPDATE
    TO vyomanaut_app
    USING (TRUE)
    WITH CHECK (
        status <> 'DELETED' OR deleted_at IS NOT NULL
    );

-- No DELETE policy is created. Any DELETE attempt — by any role, including
-- vyomanaut_app — returns permission denied. This is the fix for the
-- historical hard-delete incident: chunk_assignments rows are retired by
-- UPDATE status = 'DELETED' only, never by physical DELETE.

-- ── audit_receipt_nonces — INSERT only, replay-guard integrity ─────────────────
-- The app writes nonces here (never deletes); the migrator prunes expired nonces
-- out-of-band (BYPASSRLS). FORCE + insert-only means a compromised app credential
-- cannot delete guard rows to enable a replay. (ADR-033, DM §3 Invariant 5)
ALTER TABLE audit_receipt_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_receipt_nonces FORCE  ROW LEVEL SECURITY;

CREATE POLICY audit_receipt_nonces_app_select
    ON audit_receipt_nonces
    FOR SELECT
    TO vyomanaut_app
    USING (TRUE);

CREATE POLICY audit_receipt_nonces_insert_only
    ON audit_receipt_nonces
    FOR INSERT
    TO vyomanaut_app
    WITH CHECK (TRUE);

-- No UPDATE or DELETE policy. A nonce, once recorded, is immutable for the app.

-- ── Triggers ───────────────────────────────────────────────────────────────────
-- TODO(4.9.x): updated_at maintenance triggers from DM §9.

-- ── Materialised Views ────────────────────────────────────────────────────────
-- Refreshed asynchronously by the microservice; the underlying tables are always
-- the source of truth. Refresh is suspended when foreground DB read latency at
-- p99 approaches 50ms (ADR-025).
-- [REF: DM §7, DM §9, MVP §5.5, build.md Phase 4.7]

-- ── mv_provider_scores — three-window reliability score per provider ──────────
-- mv_provider_scores: DROPPED AND RECREATED AT STARTUP from NetworkProfile.ScoreWindow*
-- Production intervals: 24h / 7d / 30d
-- Demo intervals: 2min / 6min / 20min  (set by microservice startup, not this migration)
--
-- Used by: scoring package, release multiplier computation, assignment service.
-- CRITICAL: scores_as_of must be within 60 minutes before this view is used for
-- release multiplier computation (ADR-024) — stale scores produce wrong payments.
-- The interval literals below ('24 hours' / '7 days' / '30 days') are PRODUCTION
-- placeholders only: this view is an application-layer artifact that is DROPPED
-- and RECREATED on every microservice restart from profile.ScoreWindow{Short,
-- Medium,Long} (ADR-031, MVP §5.5). The DDL here exists so check-07's migration
-- apply/rollback gate and any fresh-clone developer have a working view before
-- the microservice has ever started once.
--
-- Milestone 8 corrections session addition (ARCH §20): "Three or more JIT
-- flags from the same provider within a rolling 7-day window triggers a
-- 0.5x weight penalty on that provider's audit passes in the 24h scoring
-- window for 30 days." The write side of this — audit_receipts.jit_flag —
-- has shipped since the Milestone 7 corrections session
-- (WriteReceiptRecordResponse, internal/audit/receipt.go); until now nothing
-- read it back. jit_penalized below is the read side.
--
-- Framed as "did a qualifying 7-day window occur at any point in the last
-- 30 days" rather than "set a flag when the 3rd one lands and expire it 30
-- days later" — the latter would need mutable, persisted state (a table
-- with its own retention/cleanup), which this view's whole design avoids:
-- it is DROPPED AND RECREATED at every microservice startup and fully
-- recomputed from audit_receipts on every REFRESH, nothing else remembered
-- in between. The two framings are logically equivalent: "some 7-day
-- window ending on a JIT-flagged receipt within the last 30 days had >= 3
-- JIT flags" is true for exactly the same span of time "the 3rd flag
-- started a 30-day penalty" would be. The partial index on
-- audit_receipts(provider_id, server_challenge_ts DESC) WHERE jit_flag,
-- already present above, supports both the outer scan and the correlated
-- COUNT below.
-- [REF: DM §7, MVP §5.5, IC §6, build.md Phase 4.7 Session 4.7.1, ARCH §20]
CREATE MATERIALIZED VIEW mv_provider_scores AS
WITH jit_penalized AS (
    SELECT DISTINCT ar.provider_id
    FROM audit_receipts ar
    WHERE ar.jit_flag = TRUE
      AND ar.abandoned_at IS NULL
      AND ar.server_challenge_ts >= NOW() - INTERVAL '30 days'
      AND (
          SELECT COUNT(*)
          FROM audit_receipts ar2
          WHERE ar2.provider_id = ar.provider_id
            AND ar2.jit_flag = TRUE
            AND ar2.abandoned_at IS NULL
            AND ar2.server_challenge_ts BETWEEN ar.server_challenge_ts - INTERVAL '7 days' AND ar.server_challenge_ts
      ) >= 3
)
SELECT
    provider_id,
    score_24h,
    score_7d,
    score_30d,
    (
        COALESCE(score_24h, 0) * 0.5 +
        COALESCE(score_7d,  0) * 0.3 +
        COALESCE(score_30d, 0) * 0.2
    ) AS score_composite,
    NOW() AS scores_as_of  -- consumers must check age before using for payment decisions
FROM (
    SELECT
        sub.provider_id,
        -- SHORT WINDOW (placeholder: 24h production; overridden at startup).
        -- ARCH §20, Milestone 8 corrections session: pass_24h is weighted
        -- 0.5x ONLY when this provider is in jit_penalized above. The 7d/30d
        -- windows below are deliberately unaffected — ARCH §20 names the
        -- 24h window specifically.
        (sub.pass_24h * (CASE WHEN jp.provider_id IS NOT NULL THEN 0.5 ELSE 1.0 END))
        / NULLIF(sub.total_24h, 0)
        AS score_24h,
        -- MEDIUM WINDOW (placeholder: 7 days production; overridden at startup)
        sub.pass_7d::FLOAT / NULLIF(sub.total_7d, 0) AS score_7d,
        -- LONG WINDOW (placeholder: 30 days production; overridden at startup)
        sub.pass_30d::FLOAT / NULLIF(sub.total_30d, 0) AS score_30d
    FROM (
        SELECT
            provider_id,
            SUM(CASE WHEN server_challenge_ts >= NOW() - INTERVAL '24 hours'
                    AND audit_result = 'PASS' THEN 1 ELSE 0 END) AS pass_24h,
            SUM(CASE WHEN server_challenge_ts >= NOW() - INTERVAL '24 hours'
                    AND audit_result IS NOT NULL THEN 1 ELSE 0 END) AS total_24h,
            SUM(CASE WHEN server_challenge_ts >= NOW() - INTERVAL '7 days'
                    AND audit_result = 'PASS' THEN 1 ELSE 0 END) AS pass_7d,
            SUM(CASE WHEN server_challenge_ts >= NOW() - INTERVAL '7 days'
                    AND audit_result IS NOT NULL THEN 1 ELSE 0 END) AS total_7d,
            SUM(CASE WHEN server_challenge_ts >= NOW() - INTERVAL '30 days'
                    AND audit_result = 'PASS' THEN 1 ELSE 0 END) AS pass_30d,
            SUM(CASE WHEN server_challenge_ts >= NOW() - INTERVAL '30 days'
                    AND audit_result IS NOT NULL THEN 1 ELSE 0 END) AS total_30d
        FROM audit_receipts
        WHERE abandoned_at IS NULL
        GROUP BY provider_id
    ) sub
    LEFT JOIN jit_penalized jp ON jp.provider_id = sub.provider_id
) scores;

CREATE UNIQUE INDEX ON mv_provider_scores (provider_id);
-- Required for REFRESH MATERIALIZED VIEW CONCURRENTLY (DM §9 checklist).

-- ── mv_provider_escrow_balance — escrow balance per provider ──────────────────
-- Used by: release computation, provider dashboard endpoint.
-- Refreshed: after each DEPOSIT, RELEASE, SEIZURE, or REVERSAL event.
-- Balance = SUM(DEPOSIT + REVERSAL) - SUM(RELEASE + SEIZURE). REVERSAL increases
-- balance (refund of a reversed payout) — DM §7 amendment.
-- idempotency_key for a REVERSAL event = SHA-256('reversal' || original_idempotency_key),
-- deterministic given the original payout's key; enforced at the application
-- layer — no DB constraint can derive it.
-- [REF: DM §7, DM §3 Invariant 2, build.md Phase 4.7 Session 4.7.2]
CREATE MATERIALIZED VIEW mv_provider_escrow_balance AS
SELECT
    provider_id,
    SUM(CASE WHEN event_type IN ('DEPOSIT', 'REVERSAL') THEN amount_paise ELSE 0 END)
    -
    SUM(CASE WHEN event_type IN ('RELEASE', 'SEIZURE') THEN amount_paise ELSE 0 END)
    AS balance_paise
FROM escrow_events
GROUP BY provider_id;

CREATE UNIQUE INDEX ON mv_provider_escrow_balance (provider_id);

-- ── mv_owner_escrow_balance — prepaid balance per data owner ───────────────────
-- Used by: FR-014 (balance check before upload), FR-021 (balance view), FR-059
-- (withdrawal). Refreshed: after each DEPOSIT, CHARGE, WITHDRAWAL, or REFUND event.
-- Balance = SUM(DEPOSIT + REFUND) - SUM(CHARGE + WITHDRAWAL), floored at zero via
-- GREATEST(..., 0) so that event-ordering races never surface a negative balance
-- to the owner dashboard (DM §7: "Add GREATEST(..., 0) to ... ensure no negative
-- values exist").
-- [REF: DM §7, FR-014, FR-021, FR-059, build.md Phase 4.7 Session 4.7.3]
CREATE MATERIALIZED VIEW mv_owner_escrow_balance AS
SELECT
    owner_id,
    GREATEST(
        SUM(CASE WHEN event_type IN ('DEPOSIT', 'REFUND') THEN amount_paise ELSE 0 END)
        -
        SUM(CASE WHEN event_type IN ('CHARGE', 'WITHDRAWAL') THEN amount_paise ELSE 0 END),
        0  -- prevents negative balance (DM §7: "Add GREATEST(..., 0)")
    ) AS balance_paise
FROM owner_escrow_events
GROUP BY owner_id;

CREATE UNIQUE INDEX ON mv_owner_escrow_balance (owner_id);

-- ── mv_segment_shard_counts — available/active shard count per segment ────────
-- Used by: repair trigger detector, file availability status in owner dashboard.
-- Refreshed: after each chunk_assignment status change.
-- available_shard_count (ACTIVE + REPAIRING) is compared against
-- profile.DataShards/LazyRepairR0 to decide THRESHOLD_WARNING / EMERGENCY_FLOOR
-- repair triggers; active_shard_count (ACTIVE only) is the count actually
-- serving retrieval traffic right now. is_vetting_chunk rows are not filtered
-- out here deliberately — a segment_id is always NULL for vetting chunks (DM
-- §8.21), so they never join into this GROUP BY in the first place.
-- [REF: DM §7, build.md Phase 4.7 Session 4.7.4]
CREATE MATERIALIZED VIEW mv_segment_shard_counts AS
SELECT
    segment_id,
    COUNT(*) FILTER (WHERE status IN ('ACTIVE', 'REPAIRING'))
        AS available_shard_count,
    COUNT(*) FILTER (WHERE status = 'ACTIVE')
        AS active_shard_count
FROM chunk_assignments
GROUP BY segment_id;

CREATE UNIQUE INDEX ON mv_segment_shard_counts (segment_id);
-- Session 4.7.5: every materialised view above has its own unique index,
-- required for REFRESH MATERIALIZED VIEW CONCURRENTLY (DM §9 checklist).
-- ── Grants ────────────────────────────────────────────────────────────────────
-- Least-privilege table grants for the non-owning service roles (ADR-032).
-- No DELETE is granted anywhere, EXCEPT pending_registrations (see below).

-- audit_receipts: INSERT (phase 1) + UPDATE (phase 2) + SELECT (read + FORCE-RLS
-- WHERE evaluation). Row scope is further constrained by the policies above.
GRANT SELECT, INSERT, UPDATE ON audit_receipts TO vyomanaut_app;
GRANT SELECT, UPDATE          ON audit_receipts TO vyomanaut_gc;

-- escrow_events: append-only ledger — INSERT + SELECT only.
GRANT SELECT, INSERT ON escrow_events TO vyomanaut_app;

-- audit_receipt_nonces: global replay guard — INSERT + SELECT only (ADR-033).
GRANT SELECT, INSERT ON audit_receipt_nonces TO vyomanaut_app;

-- otp_codes (build.md Milestone 11 Phase 11.4): OTP send INSERTs a fresh row;
-- the rate-limit check and the verify lookup both SELECT (COUNT WHERE
-- created_at > NOW() - interval, and "most recent unconsumed, unexpired code");
-- verify UPDATEs consumed_at on success. Never DELETEd -- rows are
-- soft-consumed, not removed; this is NOT an ADR-032 append-only/invariant
-- table, it just happens to have no delete path in the current design.
GRANT SELECT, INSERT, UPDATE ON otp_codes TO vyomanaut_app;

-- pending_registrations (build.md Milestone 11 Phase 11.4/11.5): written once
-- at OTP-verify time, read once and DELETEd by whichever register endpoint
-- redeems it (see the table's own doc comment: "deleted on redemption").
-- This is ordinary session-bridge state, not an ADR-032 append-only ledger,
-- so DELETE is legitimately granted here -- it is not covered by the "no
-- DELETE anywhere" rule, which applies specifically to audit_receipts,
-- escrow_events, owner_escrow_events, and the soft-delete-only tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON pending_registrations TO vyomanaut_app;

-- chunk_assignments: INSERT + UPDATE (status/soft-delete) + SELECT.
GRANT SELECT, INSERT, UPDATE ON chunk_assignments TO vyomanaut_app;

-- Non-RLS mutable operational tables the request path reads and writes. No DELETE.
GRANT SELECT, INSERT, UPDATE ON owners        TO vyomanaut_app;
GRANT SELECT, INSERT, UPDATE ON providers     TO vyomanaut_app;
GRANT SELECT, INSERT, UPDATE ON files         TO vyomanaut_app;
GRANT SELECT, INSERT, UPDATE ON audit_periods TO vyomanaut_app;
GRANT SELECT, INSERT, UPDATE ON repair_jobs   TO vyomanaut_app;

-- Append-only / write-once tables: INSERT + SELECT only.
GRANT SELECT, INSERT ON segments            TO vyomanaut_app;
GRANT SELECT, INSERT ON owner_escrow_events TO vyomanaut_app;

-- Read-only derived objects for dashboards and scheduling.
GRANT SELECT ON active_chunk_assignments TO vyomanaut_app;
GRANT SELECT ON mv_provider_scores         TO vyomanaut_app;
GRANT SELECT ON mv_provider_escrow_balance TO vyomanaut_app;
GRANT SELECT ON mv_owner_escrow_balance    TO vyomanaut_app;
GRANT SELECT ON mv_segment_shard_counts    TO vyomanaut_app;

