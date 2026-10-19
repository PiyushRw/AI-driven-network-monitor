"""SQLite event log. Every query here is a SQL lesson (see handbook)."""
import sqlite3, time
import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('alert','block','info')),
  src_ip TEXT,
  votes TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS metrics (
  ts REAL NOT NULL, bytes_in REAL, bytes_out REAL, conns INTEGER, syn_recv INTEGER
);
"""


class Store:
    def __init__(self, path=config.DB_PATH):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def event(self, kind, src_ip=None, votes=None, detail=""):
        self.db.execute("INSERT INTO events(ts,kind,src_ip,votes,detail) VALUES (?,?,?,?,?)",
                        (time.time(), kind, src_ip, str(votes), detail))   # parameterised = no SQL injection
        self.db.commit()

    def metric(self, bytes_in, bytes_out, conns, syn):
        self.db.execute("INSERT INTO metrics VALUES (?,?,?,?,?)", (time.time(), bytes_in, bytes_out, conns, syn))
        self.db.commit()

    def recent(self, n=50):
        return self.db.execute("SELECT datetime(ts,'unixepoch','localtime'),kind,src_ip,detail "
                               "FROM events ORDER BY ts DESC LIMIT ?", (n,)).fetchall()

    def top_offenders(self, n=5):
        return self.db.execute("SELECT src_ip, COUNT(*) c FROM events WHERE kind='block' "
                               "GROUP BY src_ip ORDER BY c DESC LIMIT ?", (n,)).fetchall()
