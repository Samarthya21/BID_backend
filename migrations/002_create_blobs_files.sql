
CREATE TABLE IF NOT EXISTS blobs (
  id UUID PRIMARY KEY,
  sha256 TEXT UNIQUE NOT NULL,
  size BIGINT NOT NULL,
  mime VARCHAR(255),
  storage_key TEXT NOT NULL,
  ref_count INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_blobs_sha256 ON blobs (sha256);

--metadata
CREATE TABLE IF NOT EXISTS files (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
  blob_id UUID REFERENCES blobs(id) ON DELETE RESTRICT,
  filename TEXT NOT NULL,
  mime VARCHAR(255),
  size BIGINT NOT NULL,
  is_public BOOLEAN DEFAULT FALSE,
  download_count BIGINT DEFAULT 0,
  uploaded_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_files_owner ON files (owner_id);
CREATE INDEX IF NOT EXISTS idx_files_filename ON files (filename);
