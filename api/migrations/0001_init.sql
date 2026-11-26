-- One proof job per logged reply: every challenge on the same reply shares it.
CREATE TABLE jobs (
  request_id   TEXT PRIMARY KEY,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'leased', 'done')),
  created_at   INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  lease        TEXT,
  worker       TEXT,
  leased_at    INTEGER,
  lease_until  INTEGER,
  outcome      TEXT CHECK (outcome IN ('conformant', 'deviation', 'unavailable')),
  proof_digest TEXT,
  proof_ms     INTEGER,
  done_at      INTEGER
);
CREATE INDEX jobs_queue ON jobs (state, created_at);

CREATE TABLE challenges (
  id         TEXT PRIMARY KEY,
  request_id TEXT NOT NULL, -- the job it shares with every other challenge on this reply
  role       TEXT NOT NULL CHECK (role IN ('holder', 'regulator', 'auditor', 'thirdparty')),
  challenger TEXT NOT NULL, -- SHA-256 of the caller's bearer key, never the key
  reason     TEXT NOT NULL CHECK (reason IN ('model', 'altered', 'routine')),
  note       TEXT NOT NULL DEFAULT '', -- public with the verdict
  filed_at   INTEGER NOT NULL
);
CREATE INDEX challenges_recent ON challenges (filed_at);
CREATE INDEX challenges_by_challenger ON challenges (challenger, filed_at);
CREATE INDEX challenges_by_request ON challenges (request_id, filed_at);
