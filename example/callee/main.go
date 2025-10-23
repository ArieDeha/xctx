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

// Command callee
//
// This is the receiving side of the xctx demo. It shows how a service can:
//  1. Build an xctx *Codec* for a *typed* payload.
//  2. Parse the encrypted "X-Context" header from inbound requests.
//  3. Validate claims (issuer/audience/time) and inject the typed struct into
//     the request context.
//  4. Read that typed struct in handlers without ever touching maps or
//     reflection.
//
// Quick start (local demo):
//
//	# Terminal A – start the callee (this process)
//	go run ./example/callee
//
//	# Terminal B – start the matching caller example (issues the header)
//	go run ./example/caller
//
//	# Call the callee endpoint; it will show the values from the propagated ctx
//	curl -s http://127.0.0.1:8081/whoami | jq
//
// Configuration:
//
//	The callee pulls configuration from two sources and merges them:
//	  • Environment (see variables below)
//	  • A local "user" Config literal (sane defaults for demo)
//	The merge is: env → overridden by user → defaults → validated.
//
//	Recognized environment variables (optional unless noted):
//	  XCTX_HEADER_NAME     – header name (default: "X-Context")
//	  XCTX_ISSUER          – expected issuer (optional)
//	  XCTX_AUDIENCE        – expected audience (optional)
//	  XCTX_TTL             – duration, e.g. "2m" (default: 5m)
//	  XCTX_CURRENT_KID     – current key id (required if user config omits it)
//	  XCTX_CURRENT_KEY     – current 32B key; hex/base64/raw accepted
//	  XCTX_OTHER_KEYS      – CSV of kid=key for accepted old keys
//	  XCTX_TYPED_KEY_NAME  – local-only name for the typed key (default: "xctx")
//
// Security notes:
//   - The header is sealed with AES‑256‑GCM. Decryption also validates integrity
//     (tamper resistance) and checks time-window constraints (nbf/exp).
//   - Issuer/Audience checks are enforced when configured on both sides.
//   - Additional Authenticated Data (AAD) can be configured at codec build time,
//     but must match **exactly** between caller and callee. For simplicity this
//     demo does not set AAD; to enable it, provide the same binder function to
//     BuildCodecFromEnvWithKey on both sides.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	xctx "github.com/ArieDeha/xctx"
)

// PassingContext is the *typed* payload we propagate between services.
// You decide the schema; the library never reflects or inspects it.
type PassingContext struct {
	UserID   int32  `json:"uid"`
	UserName string `json:"un"`
	Role     string `json:"role,omitempty"`
}

// serverDeps groups runtime dependencies the handlers need: the xctx codec and
// the typed key used to retrieve the injected struct from request contexts.
type serverDeps struct {
	codec *xctx.Codec[PassingContext]
	tkey  xctx.TypedKey[PassingContext]
}

// main wires configuration, builds the xctx codec, installs a middleware that
// parses the header into the request context, and serves an example endpoint.
func main() {
	// --- 1) Define user overrides (kept small; env can replace any field) ---
	user := xctx.Config{
		HeaderName: xctx.DefaultHeaderName, // keep the default; override via env if needed
		Issuer:     "svc-caller",           // what we expect the caller to set as issuer
		Audience:   "svc-callee",           // who the token targets (this service)
		TTL:        2 * time.Minute,        // acceptable lifetime

		// For local demo we inline a key; prefer env or a secret store in prod.
		CurrentKID: "kid-demo",
		CurrentKey: []byte("0123456789abcdef0123456789abcdef"), // MUST be 32 bytes
		// OtherKeys: map[string][]byte{"old": <32B>}, // accept previous keys if rotating
		// TypedKeyName: "xctx", // optional; default is "xctx"
	}

	// --- 2) Build codec & typed key from env + user config ---
	codec, typedKey, err := xctx.BuildCodecFromEnvWithKey[PassingContext](user, nil /* auto-create key from TypedKeyName */, nil /* no AAD for this demo */)
	if err != nil {
		log.Fatalf("xctx: build codec: %v", err)
	}

	deps := &serverDeps{codec: codec, tkey: typedKey}

	mux := http.NewServeMux()
	mux.Handle("/whoami", deps.ctxMiddleware(http.HandlerFunc(deps.handleWhoAmI)))

	log.Printf("callee listening on :8081 …")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatal(err)
	}
}

// ctxMiddleware parses the encrypted header using the codec and, on success,
// injects the typed PassingContext into a derived request context.
//
// Failure policy:
//   - Missing/invalid header → 401 Unauthorized (adjust for your app needs).
//   - On success, the next handler sees r.Context() carrying PassingContext.
func (s *serverDeps) ctxMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, _, err := s.codec.ParseCtx(r)
		if err != nil {
			// You can examine err.Error() to distinguish causes (unknown kid, time, etc.).
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleWhoAmI reads the typed value from the request context using the typed
// key and emits a small JSON response.
//
// This demonstrates that the rest of your application logic never needs to
// know about header formats, cryptography, or generic maps—it just reads a
// typed struct from context.
func (s *serverDeps) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	pc, _ := r.Context().Value(s.tkey).(PassingContext) // zero if absent (middleware guards it)
	resp := map[string]any{
		"ok":   true,
		"user": pc,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
