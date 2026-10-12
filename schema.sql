-- Users: auth, currency, progression
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  coins         INTEGER DEFAULT 200,
  wins          INTEGER DEFAULT 0,
  losses        INTEGER DEFAULT 0,
  rank_points   INTEGER DEFAULT 100,
  character_id  TEXT DEFAULT 'mashi',
  suit_id       TEXT DEFAULT 'suit_black',
  hat_id        TEXT DEFAULT 'hat_black',
  created_at    TEXT DEFAULT (datetime('now'))
);

-- Purchased shop items
CREATE TABLE IF NOT EXISTS purchases (
  user_id INTEGER NOT NULL,
  item_id TEXT NOT NULL,
  type    TEXT NOT NULL,              -- 'suit' | 'hat'
  PRIMARY KEY (user_id, item_id)
);
