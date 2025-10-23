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

// file: ./example/caller/main.go

// Command caller
//
// This is the sending side of the xctx demo. It shows how a service can:
//  1. Build an xctx *Codec* for a *typed* payload.
//  2. Put that typed payload into a request context.
//  3. Seal the payload into a single encrypted header (default: "X-Context").
//  4. Call a downstream service (the callee), which will parse and validate it.
//
// Quick start (local demo):
//
//	# Terminal A – start the callee (receiver)
//	go run ./example/callee
//
//	# Terminal B – run the caller (this process)
//	go run ./example/caller
//
//	# You should see the callee respond with the propagated typed payload.
//
// Configuration merge order:
//   - Environment → overridden by user → defaults → validated
//     Recognized environment variables (optional unless noted):
//     XCTX_HEADER_NAME     – header name (default: "X-Context")
//     XCTX_ISSUER          – value the caller writes as issuer (optional)
//     XCTX_AUDIENCE        – value the caller writes as audience (optional)
//     XCTX_TTL             – duration, e.g. "2m" (default: 5m)
//     XCTX_CURRENT_KID     – current key id (required if user config omits it)
//     XCTX_CURRENT_KEY     – current 32B key; hex/base64/raw accepted
//     XCTX_OTHER_KEYS      – CSV of kid=key (rarely needed on caller)
//     XCTX_TYPED_KEY_NAME  – local-only name for the typed key (default: "xctx")
//
// Security notes:
//   - The header is AES‑256‑GCM sealed and authenticated.
//   - Issuer/Audience you set here must match what the callee expects.
//   - If you use AAD (additional authenticated data), both sides must supply the
//     same bytes via the builder; otherwise decryption will fail on the callee.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	xctx "github.com/ArieDeha/xctx"
)

// PassingContext is the *typed* payload we propagate to the callee.
// Keep it compact to avoid large headers; the library never inspects it.
type PassingContext struct {
	UserID   int32  `json:"uid"`
	UserName string `json:"un"`
	Role     string `json:"role,omitempty"`
}

// main wires configuration, builds the xctx codec, constructs a sample payload,
// embeds it into the outbound request as a sealed header, and prints callee's
// JSON response.
func main() {
	calleeURL := getenv("CALLEE_URL", "http://127.0.0.1:8081/whoami")

	// --- 1) Define user overrides (env can replace any field) ---
	user := xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-caller", // the callee will expect this
		Audience:   "svc-callee", // target audience (the callee)
		TTL:        2 * time.Minute,

		// For demo we inline a key; in production prefer env or a secret store.
		CurrentKID: "kid-demo",
		CurrentKey: []byte("0123456789abcdef0123456789abcdef"), // MUST be 32 bytes
		// OtherKeys: map[string][]byte{"old": <32B>},
		// TypedKeyName: "xctx", // optional local-only name
	}

	// --- 2) Build codec & typed key from env + user config ---
	codec, typedKey, err := xctx.BuildCodecFromEnvWithKey[PassingContext](user, nil /* auto-create key from TypedKeyName */, nil /* no AAD for this demo */)
	if err != nil {
		log.Fatalf("xctx: build codec: %v", err)
	}

	// --- 3) Craft the typed payload we want to propagate ---
	pc := PassingContext{UserID: 42, UserName: "arie", Role: "admin"}

	// --- 4) Build request, put typed value in context, and seal header ---
	req, err := http.NewRequest(http.MethodGet, calleeURL, nil)
	if err != nil {
		log.Fatalf("new request: %v", err)
	}

	ctx := xctx.DefaultInjector[PassingContext](typedKey)(req.Context(), pc)
	if err := codec.SetHeader(req, ctx); err != nil {
		log.Fatalf("embed header: %v", err)
	}

	// --- 5) Send and pretty-print the JSON response ---
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("http do: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	pretty := prettyJSON(body)
	fmt.Printf("HTTP %d\n%s\n", resp.StatusCode, pretty)
}

// prettyJSON attempts to format JSON or falls back to raw body.
func prettyJSON(b []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return string(b)
	}
	return buf.String()
}

// getenv returns env[k] or def if unset/empty.
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
