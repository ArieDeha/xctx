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

// file: ./xctx_blackbox_test.go

package xctx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xctx "github.com/ArieDeha/xctx"
)

// PassingContext is the typed payload we propagate end-to-end in black-box
// tests. Keeping it small avoids header bloat and isolates behavior under test.
type PassingContext struct {
	UserID   int32  `json:"uid"`
	UserName string `json:"un"`
	Role     string `json:"role,omitempty"`
}

// newKey returns a 32-byte AES key filled with the provided byte. This helps us
// generate distinct-but-deterministic keys for client/server without coupling
// to any internals of the xctx package.
func newKey(b byte) []byte {
	return []byte{
		b, b, b, b, b, b, b, b,
		b, b, b, b, b, b, b, b,
		b, b, b, b, b, b, b, b,
		b, b, b, b, b, b, b, b,
	}
}

// newCodecFromUserCfg builds a codec+typedKey using the high-level helper that
// merges env + overrides and auto-creates the TypedKey (when nil).
func newCodecFromUserCfg(t *testing.T, user xctx.Config, aad func() []byte) (*xctx.Codec[PassingContext], xctx.TypedKey[PassingContext]) {
	t.Helper()
	codec, key, err := xctx.BuildCodecFromEnvWithKey[PassingContext](user, nil, aad)
	if err != nil {
		t.Fatalf("build codec: %v", err)
	}
	return codec, key
}

// TestRoundTrip_Success (Purpose)
//
//	Validates the happy-path: a caller embeds the header and the callee parses
//	it, yielding the same typed struct and injecting it into the new context.
//
// (How)
//  1. Build client & server with the same KID/key and default options.
//  2. Put PassingContext into the request context on the client.
//  3. client.SetHeader embeds X-Context.
//  4. server.ParseCtx returns the typed value and derived context.
func TestRoundTrip_Success(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidA",
		CurrentKey: newKey(1),
	}, nil)

	server, sKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidA",
		CurrentKey: newKey(1),
	}, nil)
	_ = sKey // server codec already holds injector for its own key

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{UserID: 7, UserName: "arie"})

	r := httptest.NewRequest(http.MethodGet, "http://test/greet", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}

	ctx2, pc, err := server.ParseCtx(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pc.UserID != 7 || pc.UserName != "arie" {
		t.Fatalf("unexpected pc: %+v", pc)
	}
	if got := ctx2.Value(sKey).(PassingContext); got.UserID != 7 {
		t.Fatal("inject failed")
	}
}

// TestHeaderNameOverride (Purpose)
//
//	Verifies that a custom header name is honored on both sides.
//
// (How)
//
//	Configure client and server with HeaderName "X-Ctx" and assert ParseCtx succeeds.
func TestHeaderNameOverride(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: "X-Ctx",
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kid",
		CurrentKey: newKey(2),
	}, nil)
	server, sKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: "X-Ctx",
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kid",
		CurrentKey: newKey(2),
	}, nil)

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{UserID: 1})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}

	if _, _, err := server.ParseCtx(r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = sKey
}

// TestIssuerAudienceMismatch (Purpose)
//
//	Ensures audience/issuer checks are enforced when configured.
//
// (How)
//
//	Client issues with issuer=a, audience=b; server expects a different audience;
//	ParseCtx must fail.
func TestIssuerAudienceMismatch(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidX",
		CurrentKey: newKey(3),
	}, nil)
	server, _ := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-OTHER",
		TTL:        2 * time.Minute,
		CurrentKID: "kidX",
		CurrentKey: newKey(3),
	}, nil)

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected audience error")
	}
}

// TestUnknownKID (Purpose)
//
//	Confirms that tokens produced with a KID unknown to the server are rejected.
//
// (How)
//
//	Client uses kidA; server current kid is kidB and does not list kidA in
//	accepted Others; ParseCtx must error with unknown kid.
func TestUnknownKID(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidA",
		CurrentKey: newKey(4),
	}, nil)

	server, _ := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidB", // different current KID; not accepting kidA
		CurrentKey: newKey(4),
	}, nil)

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected unknown kid error")
	}
}

// TestWrongKeySameKID (Purpose)
//
//	Demonstrates that sharing a KID but using different key material results in
//	authentication failure (tamper detection via GCM tag).
//
// (How)
//
//	Client and server both use "kidA" but different 32-byte keys; ParseCtx must
//	fail during AEAD open.
func TestWrongKeySameKID(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidA",
		CurrentKey: newKey(5),
	}, nil)

	server, _ := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kidA", // same kid, different key
		CurrentKey: newKey(6),
	}, nil)

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected decrypt failure")
	}
}

// TestBadVersionAndMalformed (Purpose)
//
//	Validates top-level header parsing guards without crafting internal
//	envelopes.
//
// (How)
//  1. Missing header -> error.
//  2. Wrong textual prefix (v2.) -> error.
//  3. Malformed base64 after v1. -> error.
func TestBadVersionAndMalformed(t *testing.T) {
	server, _ := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		CurrentKID: "kid",
		CurrentKey: newKey(7),
		TTL:        time.Minute,
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	// missing
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected missing header error")
	}
	// bad version
	r.Header.Set("X-Context", "v2.something")
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected bad version error")
	}
	// malformed base64 / envelope
	r.Header.Set("X-Context", "v1.not-base64$$$")
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected bad envelope error")
	}
}

// TestAADMismatch (Purpose)
//
//	Proves that AAD binding is enforced: a header minted with one AAD cannot be
//	parsed with a different AAD on the server.
//
// (How)
//
//	Client and server use different AAD binder functions; ParseCtx must
//	return an error.
func TestAADMismatch(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		TTL:        time.Minute,
		CurrentKID: "kid",
		CurrentKey: newKey(8),
	}, func() []byte { return []byte("A") })

	server, _ := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		TTL:        time.Minute,
		CurrentKID: "kid",
		CurrentKey: newKey(8),
	}, func() []byte { return []byte("B") })

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected decrypt failure due to AAD mismatch")
	}
}

// TestRotationAcceptsOldKey (Purpose)
//
//	Verifies key rotation: server advertises a new current KID but accepts the
//	previous key via the `others` map, allowing tokens issued by clients still
//	on the old key to be parsed successfully.
//
// (How)
//
//	Client issues with kid "old"; server current kid is "new" but includes
//	{"old": oldKey} in others; ParseCtx must succeed.
func TestRotationAcceptsOldKey(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		TTL:        time.Minute,
		CurrentKID: "old",
		CurrentKey: newKey(9),
	}, nil)

	server, _ := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		TTL:        time.Minute,
		CurrentKID: "new",
		CurrentKey: newKey(10),
		OtherKeys:  map[string][]byte{"old": newKey(9)},
	}, nil)

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{UserID: 1})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err != nil {
		t.Fatalf("rotation parse failed: %v", err)
	}
}

// TestSetHeaderConvenience (Purpose)
//
//	Smoke test for the SetHeader convenience method to ensure it simply wires
//	the results of EmbedHeaderCtx onto the request.
//
// (How)
//
//	Client calls SetHeader and we assert the header is present.
func TestSetHeaderConvenience(t *testing.T) {
	client, cKey := newCodecFromUserCfg(t, xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		TTL:        time.Minute,
		CurrentKID: "kid",
		CurrentKey: newKey(11),
	}, nil)

	ctx := xctx.DefaultInjector[PassingContext](cKey)(context.Background(), PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get(xctx.DefaultHeaderName) == "" {
		t.Fatal("header not set")
	}
}
