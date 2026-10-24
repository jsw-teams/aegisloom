# Protocol protection / 多协议防护

All profiles share route, identity, tenant, header/query rules and decision-cache checks before
origin access. Application authorization stays authoritative. This project currently has the
following coverage; local workerd verification is not a live-cloud or production rollout.

| Protocol | Implemented | Explicit gap |
| --- | --- | --- |
| HTTP JSON/text | Strict boundaries, bounded inspected request, bounded streamed response, fixed origin and authentication | No raw H2/H3 frames after platform parsing; multipart/compression require separate parsers |
| Streaming media | Explicit GET/HEAD route profile, single byte Range, MIME allowlist, header deadline, idle deadline, byte/concurrency bounds, cancellation | No codec decoding, transcoding, DRM or automatic HLS URL rewriting; backend must authorize every playlist/segment/key and handle deletion |
| WebSocket | Same IR/cache handshake inspection; browser-origin check; fixed authenticated upstream; bounded ordered bidirectional message relay, rate/queue/byte/idle/lifetime limits; real local workerd 101/echo test | Experimental Cloudflare adapter; no raw fragmentation/masking/control-frame inspection; per-isolate connection limits, no distributed connection accounting or DO hibernation |
| Binary gRPC-Web | POST/auth/header rules; bounded fully inspected request envelopes; streaming response envelopes, frame/message bounds and status-trailer validation | Experimental; no grpc-web-text, compression, protobuf field policy or client/bidirectional streaming; native HTTP/2 adapter unsupported |

## Media route

```ts
const route = {
  path: "/media/segment", methods: ["GET", "HEAD"], authenticated: true,
  media: {
    headerTimeoutMs: 10000, idleTimeoutMs: 30000, maxBytes: 268435456,
    contentTypes: ["video/mp4", "video/mp2t", "application/vnd.apple.mpegurl"],
  },
};
```

Use exact routes in v1; do not claim arbitrary dynamic paths are supported. Map resource identifiers
to an explicitly validated application route or extend route matching with regression tests first.
Multi-range requests are rejected; the origin remains responsible for range correctness against
the actual object. Responses are no-store by default; do not introduce a shared cache for private
media without ownership, cache-key and erasure tests. Requests still obey ordinary header/body
limits and rules. The header deadline ends once headers arrive. The idle deadline resets when
bytes progress; there is no fixed short total transfer deadline for this profile. Slow consumers
also consume the idle budget. A transfer exceeding its byte limit fails the stream instead of
silently truncating it as a successful body. Headers/status may already have been sent.

## WebSocket

Declare `{path: "/ws", methods: ["GET"], authenticated: true, protocol: "websocket"}`. The engine's
`inspectWebSocket` returns 204 only after all observable handshake checks/rules/caches pass; it
never opens a connection. Use `createCloudflareWebSocketGateway` from the package's
`cloudflare-websocket` export for the real upgrade. Supply verified authentication context, exact
browser origins, upstream allowlist and independent origin secret. Compression offers are not
forwarded or negotiated by this adapter. A selected subprotocol must have been offered by the
client. A missing Origin is rejected by default; non-browser service clients need an explicit
policy and real authentication.

The relay explicitly sets `binaryType` before accepting either socket and coordinates the close
handshake with half-open mode, including on newer Workers compatibility dates.
The shared `relayWebSockets` module inspects decoded text/ArrayBuffer messages in order in both
directions. Configure an optional message-policy callback for application semantics; a deny,
exception, timeout or saturated inspection queue closes both sides. Defaults: 64 KiB/message,
16 MiB/session, token bucket 100 messages/second/direction, 16 queued messages and 1 MiB queued
bytes/direction, 30 seconds idle, five minutes lifetime, 100 ms/inspection. The gateway defaults
to 64 admitted connections/handshakes per isolate. These are real safety limits; applications must
size and regression-test them. Reconnect before a lifetime/session budget is exhausted.

Cloudflare does not expose a portable send-buffer drain API. Queue/session limits bound this
relay's admitted work; platform-owned buffering, already-decoded large messages and connection
floods still need native edge protection. Ping/pong/control frames are handled by the platform.
Policy/identity revocation is checked at handshake, **not** continuously on an established socket;
expiry limits bound exposure. Immediate distributed connection revocation needs a durable session
registry/control channel and is not implemented. Message inspection is a separate experimental
callback, not a false claim that request-body IR rules inspect every socket message.

## gRPC-Web and native gRPC

Declare a POST route with `body: "grpc-web"` and:

```ts
grpcWeb: {
  maxMessageBytes: 262144, maxMessages: 1000, headerTimeoutMs: 10000,
  idleTimeoutMs: 30000, maxResponseBytes: 16777216,
}
```

The request is bounded by the ordinary request-body limit and fully validated before forwarding.
Response envelopes are checked incrementally across arbitrary chunk boundaries. Compressed or
unknown flags, excessive frames, truncation, data after trailers and missing/invalid/duplicate
status trailers fail closed. Protobuf data is opaque; text/JSON body rules are rejected at startup
when a binary gRPC-Web route is configured, rather than silently skipped. Application protobuf
schema validation and method/object authorization remain required. Streaming responses can expose
earlier validated bytes before a malformed later frame is detected; the stream then fails.

Cloudflare's [August 2026 announcement](https://blog.cloudflare.com/grpc-workers/) describes
private-beta gRPC-Web translation for unary/server streaming and a Containers path for full
duplex. This is not a guarantee of availability on the operator's account. The present Worker
adapter does not enable these features or implement raw native H2/trailers; native `application/grpc`
is explicitly rejected. A verified Cloudflare translation path or a separate HTTP/2-aware ingress
can be added as its own adapter with real interoperability, trailers, cancellation, deadlines and
message-limit tests. Merely tunneling opaque TCP is not application-layer gRPC protection.

中文：WS、媒体和 gRPC-Web 已有实际代码与回归测试。原生 gRPC 尚不能宣称支持；已有流中的
即时撤销、protobuf 字段授权及平台底层报文防护仍有明确边界。业务接替测试必须保持旧入口
可用，先验证正常播放、拖动、鉴权、断线和回滚，不在现网发送破坏性探测。

References: [Cloudflare WebSockets](https://developers.cloudflare.com/workers/runtime-apis/websockets/),
[gRPC-Web protocol](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md).
