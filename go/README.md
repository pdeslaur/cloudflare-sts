# Go packages

The Go module `github.com/pdeslaur/cloudflare-sts` holds these packages, for
workloads that call the broker with their SPIFFE JWT-SVID:

| Package | What it is |
|---|---|
| [`cloudflarests`](cloudflarests) | A client for the broker's tunnel, email and ACME endpoints, fetching a JWT-SVID for each call. |
| [`caddydns`](caddydns) | A Caddy DNS provider, `dns.providers.cloudflare_sts`, that answers ACME DNS-01 challenges through the broker, so Caddy holds no DNS token. |

## caddydns

Build Caddy with it by importing it beside Caddy's standard modules:

```go
import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/pdeslaur/cloudflare-sts/go/caddydns"
)
```

and point a site's `tls` at it, with `SPIFFE_ENDPOINT_SOCKET` naming the
Workload API:

```caddyfile
tls {
	dns cloudflare_sts {
		url     https://cloudflare-sts.example.com
		profile spiffe://example.com/svc/app:acme
	}
}
```

The broker writes each challenge's TXT record itself, only for the names the
workload's acme profile lists.

## Development

```sh
go vet ./... && go test -race ./...
```

The module is released with the broker, from the same `vX.Y.Z` tag.
