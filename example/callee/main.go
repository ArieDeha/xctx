// SPDX-License-Identifier: Apache-2.0
// Command callee is a tiny HTTP server demonstrating how to consume the xctx SDK
// (published as a 3rd-party Go module) to parse/verify an incoming context header,
// optionally mutate the context (business-level), and relay to other services by
// re-sealing the context.
//
// Endpoints:
//
//	GET /whoami                    -> decode & echo current context
//	GET /update                    -> mutate (+go/|go) and echo
//	GET /relay/php                 -> reseal & proxy to http://127.0.0.1:8082/whoami
//	GET /relay/php/update          -> reseal & proxy to http://127.0.0.1:8082/update
//	GET /relay/node                -> reseal & proxy to http://127.0.0.1:8083/whoami
//	GET /relay/node/update         -> reseal & proxy to http://127.0.0.1:8083/update
//	GET /relay/node-express        -> reseal & proxy to http://127.0.0.1:8084/whoami
//	GET /relay/node-express/update -> reseal & proxy to http://127.0.0.1:8084/update
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

// PassingContext represents the payload we carry across services.
// Keep it small; this is request-scoped metadata, not a data store.
type PassingContext struct {
	UserID   int    `json:"user_id"`
	UserName string `json:"user_name"`
	Role     string `json:"role,omitempty"`
}

// Demo_config holds our example configuration (replace with env/secret store in real apps).
// These must be aligned across languages so the wire format interops.
var (
	headerName = "X-Context"
	issuer     = "svc-caller"
	audience   = "svc-callee"
	ttl        = 120 * time.Second

	activeKID = "kid-demo"
	// 32-byte key; NEVER hard-code keys in real services.
	activeKey = []byte("0123456789abcdef0123456789abcdef")

	// Additional authenticated data (tenant/env). Must match across the hop.
	aadBytes = []byte("TENANT=blue|ENV=dev")
)

// Global codec and typed-key/injector/extractor.
var (
	// Typed key used by the default injector/extractor to store/retrieve PassingContext in context.Context.
	ctxKey   = xctx.NewTypedKey[PassingContext]("passing")
	injector = xctx.DefaultInjector(ctxKey)
	_        = injector
	// extractor is used internally by ParseCtx through options below; included for clarity.
	extractor = xctx.DefaultExtractor(ctxKey)
	_         = extractor

	codec *xctx.Codec[PassingContext]
)

// initCodec builds the xctx codec with a keyring and options.
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
		// Use default injector/extractor so EmbedHeaderCtx/ParseCtx operate on context.
		xctx.WithInjector[PassingContext](injector),
		xctx.WithExtractor[PassingContext](extractor),
	)
}

// nodeUpdate mutates the context for /update to demonstrate business-level changes at this hop.
func nodeUpdate(in PassingContext) PassingContext {
	out := in
	if out.UserName == "" {
		out.UserName = "go"
	} else {
		out.UserName = out.UserName + "+go"
	}
	if out.Role == "" {
		out.Role = "go"
	} else {
		out.Role = out.Role + "|go"
	}
	return out
}

// writeJSON writes a JSON response with status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// proxyWithContext reseals the context onto a new outbound request and proxies the response.
func proxyWithContext(w http.ResponseWriter, r *http.Request, target string, ctxIn context.Context) {
	req, err := http.NewRequestWithContext(ctxIn, http.MethodGet, target, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("build request: %v", err),
		})
		return
	}
	if err := codec.SetHeader(req, ctxIn); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("set header: %v", err),
		})
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("proxy: %v", err),
		})
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(b)
}

// whoamiHandler parses the incoming context and echoes it back.
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	ctx2, payload, err := codec.ParseCtx(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"server": "go-callee",
			"error":  err.Error(),
		})
		return
	}
	_ = ctx2 // ctx2 carries the typed payload for downstream calls if needed
	writeJSON(w, http.StatusOK, map[string]any{
		"server": "go-callee",
		"ctx":    payload,
	})
}

// updateHandler parses, mutates (+go/|go), and returns both previous and updated contexts.
func updateHandler(w http.ResponseWriter, r *http.Request) {
	_, payload, err := codec.ParseCtx(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"server": "go-callee",
			"error":  err.Error(),
		})
		return
	}
	updated := nodeUpdate(payload)
	// Re-inject the updated payload if you want to forward from here (not needed for echo).
	// ctx2 = injector(ctx2, updated)
	writeJSON(w, http.StatusOK, map[string]any{
		"server":      "go-callee",
		"prev_ctx":    payload,
		"updated_ctx": updated,
	})
}

// relayHandler reseals the context to a target service and returns that service's response.
func relayHandler(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx2, payload, err := codec.ParseCtx(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"server": "go-callee",
				"error":  err.Error(),
			})
			return
		}
		// Ensure the typed payload is present in context before resealing.
		ctx2 = injector(ctx2, payload)
		proxyWithContext(w, r, target, ctx2)
	}
}

func main() {
	initCodec()

	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", whoamiHandler)
	mux.HandleFunc("/update", updateHandler)

	// Relays
	mux.HandleFunc("/relay/php", relayHandler("http://127.0.0.1:8082/whoami"))
	mux.HandleFunc("/relay/php/update", relayHandler("http://127.0.0.1:8082/update"))
	mux.HandleFunc("/relay/node", relayHandler("http://127.0.0.1:8083/whoami"))
	mux.HandleFunc("/relay/node/update", relayHandler("http://127.0.0.1:8083/update"))
	mux.HandleFunc("/relay/node-express", relayHandler("http://127.0.0.1:8084/whoami"))
	mux.HandleFunc("/relay/node-express/update", relayHandler("http://127.0.0.1:8084/update"))

	addr := "127.0.0.1:8081"
	log.Printf("[go-callee] listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
