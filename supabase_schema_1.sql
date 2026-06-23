-- ============================================================
-- Supabase table for TEAM scheme verified credentials
-- Matches the actual schema Gautam has set up
-- ============================================================

CREATE TABLE IF NOT EXISTS team_credentials (
    "Provider ID"                TEXT NOT NULL,
    "TEAM ID"                    TEXT NOT NULL,
    "Udyam Number"               TEXT NULL,
    "Udyam Verification Status"  TEXT NULL,
    "Major Activity"             TEXT NULL,
    "Enterprise Type"            TEXT NULL,
    "Verified by"                TEXT NULL,
    "Verification timestamp"     TEXT NULL,

    PRIMARY KEY ("TEAM ID")
);

-- Index for the by-provider lookup endpoint
CREATE INDEX IF NOT EXISTS idx_team_creds_provider
    ON team_credentials ("Provider ID");

-- ============================================================
-- Sample data (remove in production)
-- ============================================================
INSERT INTO team_credentials (
    "Provider ID", "TEAM ID", "Udyam Number",
    "Udyam Verification Status", "Major Activity",
    "Enterprise Type", "Verified by", "Verification timestamp"
)
VALUES
    ('P001-tipplr-1234', 'TEAM-2024-000001', 'UDYAM-HR-01-0000001',
     'verified', 'Manufacturing', 'Micro',
     'Digio', '2025-03-15T10:30:00Z'),

    ('P002-waayu-5678', 'TEAM-2024-000002', 'UDYAM-MH-02-0000002',
     'verified', 'Trading', 'Small',
     'Digio', '2025-03-20T14:00:00Z'),

    ('P003-magicpin-91', 'TEAM-2024-000003', 'UDYAM-DL-03-0000003',
     'verified', 'Services', 'Micro',
     'Digio', '2025-04-01T09:15:00Z')
ON CONFLICT ("TEAM ID") DO NOTHING;
