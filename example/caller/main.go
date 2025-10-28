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

// file: ./example/caller/main.go

// Go xctx “caller” program.
// Produces a typed context, seals it into X-Context using EmbedHeaderCtx(ctx),
// and calls both the Go callee (:8081) and the PHP callee (:8082), including
// the two relay scenarios with context mutation.
//
// Key points
// ----------
//   - To seal, we must put the typed value into a Context using the SAME
//     TypedKey[T] instance the codec’s DefaultExtractor expects.
//   - We obtain that TypedKey[T] from BuildCodecFromEnvWithKey(...).
//   - We then call codec.EmbedHeaderCtx(ctx) to get ("X-Context", value).
//
// Endpoints called
// ----------------
// 1) /whoami on both Golang and PHP callees
// 2) /relay/php and /relay/go (simple relays)
// 3) /relay/php/update (Chain A: Go → PHP.update → Go.update)
// 4) /relay/go/update  (Chain B: PHP → Go.update → PHP back to caller)
//
// Run
// ---
//
//	go run ./example/caller
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

type PassingContext struct {
	UserID   int32  `json:"user_id"`
	UserName string `json:"user_name"`
	Role     string `json:"role,omitempty"`
}

type chainAResp struct {
	Server     string         `json:"server"`
	Prev       PassingContext `json:"prev_ctx"`
	PHPUpdated PassingContext `json:"php_updated_ctx"`
	GoUpdated  PassingContext `json:"go_updated_ctx"`
	Error      string         `json:"error,omitempty"`
}

type chainBResp struct {
	Server  string         `json:"server"`
	Prev    PassingContext `json:"prev_ctx"`
	Updated PassingContext `json:"updated_ctx"`
	Error   string         `json:"error,omitempty"`
}

func main() {
	// 1) Build a Codec and obtain a process-unique TypedKey[T].
	user := xctx.Config{
		HeaderName:   "X-Context",
		Issuer:       "svc-caller",
		Audience:     "svc-callee",
		TTL:          2 * time.Minute,
		CurrentKID:   "kid-demo",
		CurrentKey:   []byte("0123456789abcdef0123456789abcdef"),
		TypedKeyName: "xctx",
	}
	aad := func() []byte { return []byte("TENANT=blue|ENV=dev") }

	codec, typedKey, err := xctx.BuildCodecFromEnvWithKey[PassingContext](user, nil, aad)
	if err != nil {
		log.Fatalf("codec build: %v", err)
	}

	// 2) Create our typed payload and seal it into X-Context.
	payload := PassingContext{UserID: 7, UserName: "arie", Role: "admin"}

	// Place payload into a Context using SAME TypedKey the codec expects.
	ctx := xctx.DefaultInjector[PassingContext](typedKey)(context.Background(), payload)

	// Seal to ("X-Context", "v1.<...>").
	name, value, err := codec.EmbedHeaderCtx(ctx)
	if err != nil {
		log.Fatalf("embed: %v", err)
	}

	// Helper: GET url with our header and print the body.
	call := func(url string) string {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		req.Header.Set(name, value)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("GET %s: %v", url, err)
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("\n== %s [%d] ==\n%s\n", url, resp.StatusCode, string(body))
		return string(body)
	}

	// 3) Basic calls + simple relays
	_ = call("http://127.0.0.1:8081/whoami")    // Go callee
	_ = call("http://127.0.0.1:8082/whoami")    // PHP callee
	_ = call("http://127.0.0.1:8083/whoami")    // Node callee
	_ = call("http://127.0.0.1:8081/relay/php") // Go → PHP relay
	_ = call("http://127.0.0.1:8082/relay/go")  // PHP → Go relay
	_ = call("http://127.0.0.1:8083/relay/go")  // Node → Go relay
	_ = call("http://127.0.0.1:8083/relay/php") // Node → PHP relay

	// 4) Chain A: caller → go → php(update) → go(update) → caller
	{
		body := call("http://127.0.0.1:8081/relay/php/update")
		var out chainAResp
		_ = json.Unmarshal([]byte(body), &out)
		if out.Server != "" {
			fmt.Printf("\n[Chain A] prev        = %+v\n", out.Prev)
			fmt.Printf("[Chain A] php-updated = %+v\n", out.PHPUpdated)
			fmt.Printf("[Chain A] go-updated  = %+v\n", out.GoUpdated)
		}
	}

	// 5) Chain B: caller → php → go(update) → php → caller
	{
		body := call("http://127.0.0.1:8082/relay/go/update")
		var out chainBResp
		_ = json.Unmarshal([]byte(body), &out)
		if out.Server != "" {
			fmt.Printf("\n[Chain B] prev    = %+v\n", out.Prev)
			fmt.Printf("[Chain B] updated = %+v\n", out.Updated)
		}
	}
	// 6) Chain C: caller → go → node(update) → go(update) → caller
	{
		body := call("http://127.0.0.1:8081/relay/node/update")
		var out struct {
			Server      string         `json:"server"`
			Prev        PassingContext `json:"prev_ctx"`
			NodeUpdated PassingContext `json:"node_updated_ctx"`
			GoUpdated   PassingContext `json:"go_updated_ctx"`
		}
		_ = json.Unmarshal([]byte(body), &out)
		if out.Server != "" {
			fmt.Printf("\n[Chain C] prev        = %+v\n", out.Prev)
			fmt.Printf("[Chain C] node-updated = %+v\n", out.NodeUpdated)
			fmt.Printf("[Chain C] go-updated   = %+v\n", out.GoUpdated)
		}
	}

}
