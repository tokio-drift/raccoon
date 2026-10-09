# RACCOON HTTP API

The API is served on `127.0.0.1` only. Every response is JSON unless noted.
Timestamps are RFC 3339 with nanosecond precision in UTC (internally they are
Unix nanoseconds). Field names are camelCase.

## Authentication

Every request must carry the session token in the header:

```
X-Raccoon-Token: <token>
```

The token is printed by the CLI as part of the dashboard URL. When the browser
opens `GET /?t=<token>` the page stores the token in memory and removes it from
the address bar; subsequent API calls send it as a header.

Requests with a missing or incorrect token receive `401`. Requests whose `Host`
is not `127.0.0.1:<port>` or `localhost:<port>` receive `403`. The `Origin`
header, if present, must match the server origin; otherwise `403`.

## Errors

All errors use the same envelope:

```json
{
  "error": {
    "code": "invalid_query",
    "message": "limit must be between 1 and 1000"
  }
}
```

| HTTP status | code | When |
|---|---|---|
| 400 | `invalid_query` | malformed query or body |
| 400 | `invalid_capture` | upload is not a readable PCAP/PCAPNG |
| 400 | `payload_too_large` | upload exceeds the 500 MB cap |
| 401 | `unauthorized` | missing or wrong token |
| 403 | `forbidden` | bad `Host` or `Origin` |
| 404 | `not_found` | unknown case, stream, file or route |
| 409 | `not_ready` | analysis still running where a finished case is required |
| 500 | `internal` | unexpected server error |

---

## `POST /api/upload`

Multipart upload of a PCAP/PCAPNG. The file is streamed to disk and its header
is validated before analysis starts. Maximum size is 500 MB.

Request: `multipart/form-data` with a single `file` part.

Response `200`:

```json
{ "caseId": "20260101-120000-abcdef" }
```

Failure example `400`:

```json
{
  "error": {
    "code": "invalid_capture",
    "message": "the file does not look like a PCAP or PCAPNG capture"
  }
}
```

---

## `GET /api/case/{id}`

Case metadata and progress.

```json
{
  "id": "20260101-120000-abcdef",
  "fileName": "ftp_upload_png.pcap",
  "size": 48213,
  "pcapSha256": "9f2c...e1",
  "status": "ready",
  "stage": "done",
  "progress": 100,
  "durationNs": 2450000000,
  "packets": 42,
  "streams": 3,
  "files": 5,
  "events": 40,
  "toolVersion": "devel",
  "startedAt": "2026-01-01T12:00:00.000000000Z",
  "finishedAt": "2026-01-01T12:00:02.450000000Z",
  "error": ""
}
```

`status` is one of `queued`, `running`, `ready`, `failed`.
`stage` is one of `capture`, `decode`, `reassemble`, `analyze`, `carve`, `intel`,
`timeline`, `done`.

---

## `GET /api/case/{id}/events`

Paginated, filterable event list.

Query parameters (all optional):

| Name | Meaning |
|---|---|
| `severity` | comma-separated set: `info,warning,critical` |
| `type` | event type, e.g. `FTP_LOGIN_FAILED` |
| `phase` | `recon,access,action,exfil,c2` |
| `proto` | `ftp`, `ftp-data`, `http`, `dns`, `tcp`, `udp`, `unknown` |
| `q` | free-text search over title and details |
| `from` / `to` | RFC 3339 time bounds (inclusive/exclusive) |
| `parent` | return children of this event id |
| `flat` | `1` disables default exclusion of grouped children |
| `limit` | page size, default 200, max 1000 |
| `cursor` | opaque keyset cursor from the previous page |

Response `200`:

```json
{
  "items": [
    {
      "id": 1,
      "ts": "2026-01-01T12:00:00.100000000Z",
      "packetNo": 1,
      "packetEnd": 3,
      "type": "STREAM_OPENED",
      "severity": "info",
      "phase": "recon",
      "streamId": 1,
      "src": "10.0.0.1:50000",
      "dst": "10.0.0.2:21",
      "proto": "ftp",
      "title": "TCP stream opened 10.0.0.1:50000 -> 10.0.0.2:21",
      "details": { "midstream": false },
      "explain": "",
      "parentId": 0,
      "fileId": 0,
      "findingIds": []
    }
  ],
  "nextCursor": "MTc2NzI..."
}
```

`nextCursor` is `null`/absent when there are no further pages. Pass it back as
`cursor` unchanged. Ordering is `(ts, id)` ascending.

---

## `GET /api/case/{id}/files`

Carved files. By default files with confidence `low` are hidden; pass
`?confidence=all` to include them, or `?confidence=high|medium`.

```json
{
  "items": [
    {
      "id": 1,
      "streamId": 2,
      "dir": "c2s",
      "startOff": 0,
      "endOff": 4321,
      "format": "PNG",
      "ext": "png",
      "status": "complete",
      "confidence": "high",
      "size": 4321,
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "displayName": "secret.png",
      "path": "carved/e3b0c4...b855.png",
      "magicHex": "89504e47",
      "verdict": {
        "source": "virustotal",
        "status": "no_detections",
        "score": 0,
        "total": 70,
        "checkedAt": "2026-01-01T12:05:00.000000000Z"
      }
    }
  ]
}
```

`dir` is `c2s` or `s2c`. `status` is `complete`, `truncated` or `corrupt`.
`confidence` is `high`, `medium` or `low`. `verdict.status` is one of
`malicious`, `suspicious`, `no_detections`, `unknown`, `not_checked`. A file
without a verdict omits `verdict`.

---

## `GET /api/case/{id}/files/{fid}/download`

Returns the raw carved bytes with:

```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="<sanitized>"
X-Content-Type-Options: nosniff
```

The path is resolved solely from the database row, never from the request.

---

## `GET /api/case/{id}/streams`

Stream list; searchable by IP, port or proto.

| Name | Meaning |
|---|---|
| `q` | free text matched against src/dst `ip:port` and proto |
| `proto` | exact protocol filter |
| `limit` / `cursor` | pagination as for events |

```json
{
  "items": [
    {
      "id": 1,
      "parentId": 0,
      "proto": "ftp",
      "srcIp": "10.0.0.1",
      "srcPort": 50000,
      "dstIp": "10.0.0.2",
      "dstPort": 21,
      "startTs": "2026-01-01T12:00:00.100000000Z",
      "endTs": "2026-01-01T12:00:02.400000000Z",
      "bytesC2S": 134,
      "bytesS2C": 402,
      "packets": 14,
      "firstPacket": 1,
      "lastPacket": 14,
      "midstream": false,
      "hasGaps": false,
      "udp": false
    }
  ],
  "nextCursor": null
}
```

---

## `GET /api/case/{id}/streams/{sid}/bytes`

Reads a window of the reassembled stream.

| Name | Meaning |
|---|---|
| `dir` | required: `c2s` or `s2c` |
| `offset` | byte offset into the reassembled direction, default 0 |
| `len` | number of bytes, default 4096, clamped to 65536 |

The response includes `dataBase64` (the requested window) plus the segment
ranges that overlap it (for direction colouring) and carved file ranges that
fall inside the window.

```json
{
  "streamId": 1,
  "dir": "c2s",
  "offset": 0,
  "length": 64,
  "total": 134,
  "dataBase64": "VVNFUiBib2IA",
  "segments": [
    { "off": 0, "len": 32, "ts": "2026-01-01T12:00:00.500000000Z", "packetNo": 5 }
  ],
  "carved": [
    { "fileId": 1, "start": 0, "end": 64 }
  ]
}
```

---

## `GET /api/case/{id}/graph`

Reserved for the network graph view (PLUS-F). Returns nodes and edges.

```json
{
  "nodes": [
    { "id": "10.0.0.1", "role": "client", "bytes": 134, "severity": "info" }
  ],
  "edges": [
    {
      "src": "10.0.0.1",
      "dst": "10.0.0.2",
      "proto": "ftp",
      "streams": 1,
      "bytes": 536,
      "firstTs": "2026-01-01T12:00:00.100000000Z",
      "lastTs": "2026-01-01T12:00:02.400000000Z",
      "severity": "info"
    }
  ]
}
```

---

## `GET /api/case/{id}/report`

`?format=pdf|html|json` (default `html`). Returns the rendered report:

- `pdf` → `application/pdf`
- `html` → `text/html; charset=utf-8`
- `json` → `application/json`

---

## `GET /api/case/{id}/events/stream`

Server-Sent Events. Each message has an `event:` and a JSON `data:` payload.
On reconnect the server first replays current state.

| event | data |
|---|---|
| `progress` | `{"stage":"carve","percent":73,"packets":1024,"bytes":524288,"streams":12,"files":2}` |
| `ready` | `{"events":40,"files":5}` |
| `verdict` | `{"fileId":1,"sha256":"e3b0...","status":"malicious"}` |
| `done` | `{"caseId":"20260101-120000-abcdef"}` |
| `error` | `{"code":"internal","message":"..."}` |
