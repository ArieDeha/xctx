// SPDX-License-Identifier: Apache-2.0
// Command caller demonstrates producing an outbound sealed header using the
// 3rd-party xctx module, calling multiple services (Go/PHP/Node/Node-Express),
// and printing their responses. It mirrors the Node caller flow.
//
// Calls:
//   <base>/whoami
//   <base>/update
// Then chains via Node(:8083) to its relay endpoints (including -> node-express).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	xctx "github.com/ArieDeha/xctx"
)

// PassingContext must match the data the services expect/produce.
type PassingContext struct {
	UserID   int    `json:"user_id"`
	UserName string `json:"user_name"`
	Role     string `json:"role,omitempty"`
}

var (
	headerName = "X-Context"
	issuer     = "svc-caller"
	audience   = "svc-callee"
	ttl        = 120 * time.Second

	activeKID = "kid-demo"
	activeKey = []byte("0123456789abcdef0123456789abcdef")

	aadBytes = []byte("TENANT=blue|ENV=dev")

	ctxKey   = xctx.NewTypedKey[PassingContext]("passing")
	injector = xctx.DefaultInjector(ctxKey)

	codec *xctx.Codec[PassingContext]
)

func initCodec() {
	kr, err := xctx.NewKeyring(activeKID, activeKey, nil)
	if err != nil {
		log.Fatalf("keyring: %v", err)
	}
	codec = xctx.NewCodec[PassingContext](
		kr,
		xctx.WithHeaderName[PassingContext](headerName),
		xctx.WithIssuer[PassingContext](issuer),
		xctx.WithAudience[PassingContext](audience),
		xctx.WithTTL[PassingContext](ttl),
		xctx.WithAADBinder[PassingContext](func() []byte { return aadBytes }),
		xctx.WithInjector[PassingContext](injector),
	)
}

func logBlock(title string, status int, body any) {
	b, _ := json.MarshalIndent(body, "", "  ")
	fmt.Printf("\n== %s [%d] ==\n%s\n", title, status, string(b))
}

func doGET(ctx context.Context, url string) (int, any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	if err := codec.SetHeader(req, ctx); err != nil {
		return 0, nil, fmt.Errorf("set header: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var j any
	if json.Unmarshal(raw, &j) != nil {
		j = string(raw)
	}
	return resp.StatusCode, j, nil
}

func main() {
	initCodec()

	// Initial typed payload for the outbound request.
	payload := PassingContext{
		UserID:   7,
		UserName: "arie",
		Role:     "admin",
	}

	// Inject payload into context so EmbedHeaderCtx/SetHeader can find it.
	ctx := injector(context.Background(), payload)

	const (
		GO    = "http://127.0.0.1:8081"
		PHP   = "http://127.0.0.1:8082"
		NODE  = "http://127.0.0.1:8083"
		NODEE = "http://127.0.0.1:8084"
	)

	// whoami/update on all four callees
	for _, it := range []struct {
		name, base string
	}{
		{"go", GO},
		{"php", PHP},
		{"node", NODE},
		{"node-express", NODEE},
	} {
		if st, body, err := doGET(ctx, it.base+"/whoami"); err != nil {
			log.Printf("%s /whoami error: %v", it.name, err)
		} else {
			logBlock(it.name+" /whoami", st, body)
		}
		if st, body, err := doGET(ctx, it.base+"/update"); err != nil {
			log.Printf("%s /update error: %v", it.name, err)
		} else {
			logBlock(it.name+" /update", st, body)
		}
	}

	// Chains via Node(:8083) including relays to Node-Express(:8084)
	for _, path := range []struct {
		title, url string
	}{
		{"node → go /whoami", NODE + "/relay/go"},
		{"node → go /update", NODE + "/relay/go/update"},
		{"node → php /whoami", NODE + "/relay/php"},
		{"node → php /update", NODE + "/relay/php/update"},
		{"node → node-express /whoami", NODE + "/relay/node-express"},
		{"node → node-express /update", NODE + "/relay/node-express/update"},
	} {
		if st, body, err := doGET(ctx, path.url); err != nil {
			log.Printf("%s error: %v", path.title, err)
		} else {
			logBlock(path.title, st, body)
		}
	}
}
