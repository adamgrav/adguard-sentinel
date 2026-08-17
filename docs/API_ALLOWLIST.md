# Read-only API allowlist

The AdGuard adapter has exactly six private endpoint variants. All requests use
GET, Basic authentication, `Accept: application/json`, `Accept-Encoding:
identity`, no proxy, no redirects, a bounded timeout, and a bounded body.

| Request | Data retained |
| --- | --- |
| `GET /control/status` | version, running, protection |
| `GET /control/stats?recent=<whole-hour-ms>` | totals, processing latency, per-upstream averages, top-client ratio only |
| `GET /control/dns_info` | declared upstream set and mode |
| `GET /control/filtering/status` | required filter URL/state/count/update time |
| `GET /control/rewrite/list` | normalized rewrite tuples and enabled state |
| `GET /control/rewrite/settings` | global rewrite-enabled state |

There is no public constructor taking a method or path, no request body, and no
query-log operation. Pushover's fixed message POST belongs to a separate type
and cannot call the AdGuard origin.
