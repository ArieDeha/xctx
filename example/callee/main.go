// SPDX-License-Identifier: Apache-2.0

// Copyright 2025 Arieditya Pramadyana Deha <arieditya.prdh@live.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// file: ./example/callee/main.go

// Go xctx “callee” service (listens on :8081).
//
// What this file demonstrates
// --------------------------
//  1. How to construct a typed xctx.Codec[T] with env + overrides using
//     BuildCodecFromEnvWithKey (from xctx_config.go), which auto-wires
//     DefaultExtractor/DefaultInjector for a process-unique TypedKey[T].
//  2. How to parse an inbound header straight from *http.Request using
//     codec.ParseCtx(r) (from xctx.go).
//  3. How to re-embed a typed payload by first putting it into a Context
//     with DefaultInjector(typedKey) and then calling codec.EmbedHeaderCtx(ctx).
//  4. Plain “whoami” and “update” endpoints plus two relay flows:
//     /relay/php         – simple relay to the PHP callee /whoami
//     /relay/php/update  – Chain A: Go → PHP(update) → Go(update) → caller
//
// Every handler prints the incoming context so you can observe end-to-end flow.
//
// Run
// ---
//
//	go run ./example/callee
//
// Requires the PHP callee running at 127.0.0.1:8082 for the relay endpoints.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	xctx "github.com/ArieDeha/xctx"
)

// PassingContext is your typed payload carried between services.
// The library is schema-agnostic; you own this definition.
type PassingContext struct {
	UserID   int32  `json:"user_id"`
	UserName string `json:"user_name"`
	Role     string `json:"role,omitempty"`
}

var (
	codec    *xctx.Codec[PassingContext]   // AEAD + claims checker
	typedKey xctx.TypedKey[PassingContext] // process-unique key identity
)

// writeJSON writes JSON with the supplied HTTP status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// logCtx prints a one-line record of what we received, for observability.
func logCtx(where string, ctx PassingContext) {
	log.Printf("[%s] incoming ctx: user_id=%d user_name=%q role=%q",
		where, ctx.UserID, ctx.UserName, ctx.Role)
}

// goUpdate deterministically mutates the typed context (demo purpose only).
// Contract:
//   - user_name += "+go" (or "go" if empty)
//   - role      += "|go" (or "go" if empty)
func goUpdate(in PassingContext) PassingContext {
	out := in
	if out.UserName != "" {
		out.UserName += "+go"
	} else {
		out.UserName = "go"
	}
	if out.Role != "" {
		out.Role += "|go"
	} else {
		out.Role = "go"
	}
	return out
}

// embedTyped produces an ("X-Context", value) pair from a typed payload.
// IMPORTANT: EmbedHeaderCtx reads the payload from context via the configured
// Extractor, so we must first place the typed value into a Context using the
// SAME TypedKey[T] that the codec’s DefaultExtractor expects.
func embedTyped(v PassingContext) (name, value string, err error) {
	// Put the typed value into a fresh Context under our process-unique key.
	ctx := xctx.DefaultInjector[PassingContext](typedKey)(context.Background(), v)

	// Now seal into the header directly from Context.
	return codec.EmbedHeaderCtx(ctx) // (name="X-Context", value="v1.<...>", err)
}

// whoamiHandler parses the inbound header, logs the context, and returns it.
//
// Uses codec.ParseCtx(r) which:
//   - reads the header (default "X-Context"),
//   - decrypts & validates claims,
//   - injects T back to a derived context (when an Injector is set),
//   - returns (newCtx, typedValue, error).
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	newCtx, ctxData, err := codec.ParseCtx(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("parse failed: %v", err),
		})
		return
	}
	_ = newCtx // kept for symmetry; handlers often pass this downstream
	logCtx("go:/whoami", ctxData)

	writeJSON(w, http.StatusOK, map[string]any{
		"server": "go-callee",
		"ctx":    ctxData,
		// Claims are private to the server; this demo only returns ctx.
	})
}

// updateHandler parses → logs → mutates and returns both prev/updated.
func updateHandler(w http.ResponseWriter, r *http.Request) {
	_, prev, err := codec.ParseCtx(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("parse failed: %v", err),
		})
		return
	}
	logCtx("go:/update", prev)
	updated := goUpdate(prev)

	writeJSON(w, http.StatusOK, map[string]any{
		"server":      "go-callee",
		"prev_ctx":    prev,
		"updated_ctx": updated,
	})
}

// relayPHPWhoamiHandler is a simple relay to the PHP callee /whoami.
// Flow: parse here → re-embed → GET http://127.0.0.1:8082/whoami with X-Context.
func relayPHPWhoamiHandler(w http.ResponseWriter, r *http.Request) {
	_, ctxData, err := codec.ParseCtx(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("parse failed: %v", err),
		})
		return
	}
	logCtx("go:/relay/php", ctxData)

	name, val, err := embedTyped(ctxData)
	fmt.Println("X-Context (raw):", val)
	if strings.HasPrefix(val, "v1.") {
		dec, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(val, "v1."))
		fmt.Println("Envelope JSON:", string(dec)) // shows {"V":1,"Alg":"AES-256-GCM",...}
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("re-embed failed: %v", err),
		})
		return
	}

	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://127.0.0.1:8082/whoami", nil)
	req.Header.Set(name, val)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("forward to php failed: %v", err),
		})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// phpUpdateResp is what PHP /update returns (prev/updated).
type phpUpdateResp struct {
	Server  string         `json:"server"`
	Prev    PassingContext `json:"prev_ctx"`
	Updated PassingContext `json:"updated_ctx"`
	Error   string         `json:"error,omitempty"`
}

// relayPHPUpdateHandler implements Chain A:
// caller → go(/relay/php/update) → php(/update) → go(mutates) → caller
func relayPHPUpdateHandler(w http.ResponseWriter, r *http.Request) {
	_, original, err := codec.ParseCtx(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("parse failed: %v", err),
		})
		return
	}
	logCtx("go:/relay/php/update original", original)

	name, val, err := embedTyped(original)
	fmt.Println("X-Context (raw):", val)
	if strings.HasPrefix(val, "v1.") {
		dec, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(val, "v1."))
		fmt.Println("Envelope JSON:", string(dec)) // shows {"V":1,"Alg":"AES-256-GCM",...}
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("re-embed failed: %v", err),
		})
		return
	}

	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://127.0.0.1:8082/update", nil)
	req.Header.Set(name, val)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("forward to php failed: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	var phpOut phpUpdateResp
	if err := json.NewDecoder(resp.Body).Decode(&phpOut); err != nil || phpOut.Server == "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"server": "go-callee",
			"error":  fmt.Sprintf("bad php response: %v", err),
		})
		return
	}
	logCtx("go:/relay/php/update php-updated", phpOut.Updated)

	goUpdated := goUpdate(phpOut.Updated)

	writeJSON(w, http.StatusOK, map[string]any{
		"server":          "go-callee",
		"prev_ctx":        original,
		"php_updated_ctx": phpOut.Updated,
		"go_updated_ctx":  goUpdated,
	})
}

func main() {
	// Build codec (env + overrides) and get the process-unique TypedKey[T].
	// These helpers are defined in xctx_config.go, and they wire defaults,
	// env override, validation, plus DefaultExtractor/Injector with TypedKey.  (ref)
	// (You may also use BuildCodecWithKey if you want to supply your own key.)
	user := xctx.Config{
		HeaderName:   "X-Context",
		Issuer:       "svc-caller",
		Audience:     "svc-callee",
		TTL:          2 * time.Minute,
		CurrentKID:   "kid-demo",
		CurrentKey:   []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
		TypedKeyName: "xctx",
	}
	aad := func() []byte { return []byte("TENANT=blue|ENV=dev") }

	c, tk, err := xctx.BuildCodecFromEnvWithKey[PassingContext](user, nil, aad)
	if err != nil {
		log.Fatalf("codec build: %v", err)
	}
	codec, typedKey = c, tk

	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", whoamiHandler)
	mux.HandleFunc("/update", updateHandler)
	mux.HandleFunc("/relay/php", relayPHPWhoamiHandler)
	mux.HandleFunc("/relay/php/update", relayPHPUpdateHandler)

	srv := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Println("go-callee listening on :8081")
	log.Fatal(srv.ListenAndServe())
}
