PRAGMA journal_mode=WAL;
CREATE TABLE streams(
  id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 0, proto TEXT,
  src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
  start_ts INTEGER, end_ts INTEGER, bytes_c2s INTEGER, bytes_s2c INTEGER,
  packets INTEGER, first_packet INTEGER, last_packet INTEGER,
  midstream INTEGER, has_gaps INTEGER, udp INTEGER);
CREATE TABLE events(
  id INTEGER PRIMARY KEY, ts INTEGER, packet_no INTEGER, packet_end INTEGER,
  type TEXT, severity TEXT, phase TEXT, stream_id INTEGER, src TEXT, dst TEXT,
  proto TEXT, title TEXT, details_json TEXT, explain TEXT,
  parent_id INTEGER DEFAULT 0, file_id INTEGER DEFAULT 0, finding_ids TEXT);
CREATE TABLE files(
  id INTEGER PRIMARY KEY, stream_id INTEGER, dir INTEGER, start_off INTEGER, end_off INTEGER,
  format TEXT, ext TEXT, status TEXT, confidence TEXT, size INTEGER,
  md5 TEXT, sha256 TEXT, display_name TEXT, path TEXT, magic_hex TEXT);
CREATE TABLE verdicts(
  sha256 TEXT, source TEXT, status TEXT, score INTEGER, total INTEGER,
  detail_json TEXT, checked_at INTEGER, PRIMARY KEY(sha256, source));
CREATE TABLE findings(
  id INTEGER PRIMARY KEY, title TEXT, technique TEXT, severity TEXT,
  explanation TEXT, evidence_event_ids TEXT);
CREATE TABLE segments(
  stream_id INTEGER, dir INTEGER, stream_off INTEGER, length INTEGER, ts INTEGER, packet_no INTEGER);
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX ix_events_ts ON events(ts);
CREATE INDEX ix_events_sev ON events(severity);
CREATE INDEX ix_events_type ON events(type);
CREATE INDEX ix_events_stream ON events(stream_id);
CREATE INDEX ix_events_parent ON events(parent_id);
CREATE INDEX ix_files_sha ON files(sha256);
CREATE INDEX ix_streams_ips ON streams(src_ip, dst_ip);
CREATE INDEX ix_segments ON segments(stream_id, dir, stream_off);