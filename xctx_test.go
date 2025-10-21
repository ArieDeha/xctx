// Copyright 2025 Arieditya Pramadyana Deha <arieditya.prdh@live.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// newClientCodec constructs a client-side Codec configured with sensible
// defaults (issuer/audience/ttl) and the default typed extractor/injector. The
// function is black-box: it uses only public APIs of xctx.
func newClientCodec(t *testing.T, kid string, key []byte, opts ...xctx.Option[PassingContext]) *xctx.Codec[PassingContext] {
	t.Helper()
	kr, err := xctx.NewKeyring(kid, key, nil)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	base := []xctx.Option[PassingContext]{
		xctx.WithExtractor(xctx.DefaultExtractor[PassingContext](typedKey)),
		xctx.WithInjector(xctx.DefaultInjector[PassingContext](typedKey)),
		xctx.WithIssuer[PassingContext]("svc-A"),
		xctx.WithAudience[PassingContext]("svc-B"),
		xctx.WithTTL[PassingContext](2 * time.Minute),
	}
	base = append(base, opts...)
	return xctx.NewCodec[PassingContext](kr, base...)
}

// newServerCodec constructs a server-side Codec, optionally providing a map of
// accepted "other" keys to exercise key rotation scenarios. Only public APIs
// are used. The extractor/injector allow the parsed struct to be placed into
// the request context for downstream handlers.
func newServerCodec(t *testing.T, currentKID string, currentKey []byte, others map[string][]byte, opts ...xctx.Option[PassingContext]) *xctx.Codec[PassingContext] {
	t.Helper()
	kr, err := xctx.NewKeyring(currentKID, currentKey, others)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	base := []xctx.Option[PassingContext]{
		xctx.WithExtractor(xctx.DefaultExtractor[PassingContext](typedKey)),
		xctx.WithInjector(xctx.DefaultInjector[PassingContext](typedKey)),
		xctx.WithIssuer[PassingContext]("svc-A"),
		xctx.WithAudience[PassingContext]("svc-B"),
	}
	base = append(base, opts...)
	return xctx.NewCodec[PassingContext](kr, base...)
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
	client := newClientCodec(t, "kidA", newKey(1))
	server := newServerCodec(t, "kidA", newKey(1), nil)

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{UserID: 7, UserName: "arie"})

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
	if got := ctx2.Value(typedKey).(PassingContext); got.UserID != 7 {
		t.Fatal("inject failed")
	}
}

// TestHeaderNameOverride (Purpose)
//
//	Verifies that a custom header name is honored on both sides.
//
// (How)
//
//	Configure client and server with WithHeaderName("X-Ctx") and assert
//	server.ParseCtx succeeds using that header.
func TestHeaderNameOverride(t *testing.T) {
	client := newClientCodec(t, "kidA", newKey(2), xctx.WithHeaderName[PassingContext]("X-Ctx"))
	server := newServerCodec(t, "kidA", newKey(2), nil, xctx.WithHeaderName[PassingContext]("X-Ctx"))

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{UserID: 1})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}

	if _, _, err := server.ParseCtx(r); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

// TestIssuerAudienceMismatch (Purpose)
//
//	Ensures audience/issuer checks are enforced when configured.
//
// (How)
//
//	Client issues with issuer=a, audience=b; server expects audience different
//	from b; ParseCtx must fail.
func TestIssuerAudienceMismatch(t *testing.T) {
	client := newClientCodec(t, "kidA", newKey(3))
	server := newServerCodec(t, "kidA", newKey(3), nil, xctx.WithAudience[PassingContext]("svc-OTHER"))

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{})
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
//	Client uses kidA; server encrypts with kidB and does not list kidA in
//	accepted Others; ParseCtx must error with unknown kid.
func TestUnknownKID(t *testing.T) {
	client := newClientCodec(t, "kidA", newKey(4))
	server := newServerCodec(t, "kidB", newKey(4), nil) // different current KID

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{})
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
	client := newClientCodec(t, "kidA", newKey(5))
	server := newServerCodec(t, "kidA", newKey(6), nil) // same kid, different key

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{})
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
	server := newServerCodec(t, "kidA", newKey(7), nil)
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
//	Client and server use different WithAADBinder functions; ParseCtx must
//	return an error.
func TestAADMismatch(t *testing.T) {
	client := newClientCodec(t, "kidA", newKey(8), xctx.WithAADBinder[PassingContext](func() []byte { return []byte("A") }))
	server := newServerCodec(t, "kidA", newKey(8), nil, xctx.WithAADBinder[PassingContext](func() []byte { return []byte("B") }))

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected decrypt failure due to AAD mismatch")
	}
}

// TestExpiryImmediate (Purpose)
//
//	Ensures the time window checks are enforced. Using a negative TTL produces
//	an already-expired token that the server must reject.
//
// (How)
//
//	Client codec is configured with WithTTL(-1s); ParseCtx should fail.
func TestExpiryImmediate(t *testing.T) {
	client := newClientCodec(t, "kidA", newKey(9), xctx.WithTTL[PassingContext](-1*time.Second))
	server := newServerCodec(t, "kidA", newKey(9), nil)

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	_ = client.SetHeader(r, ctx)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected time validity error")
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
	client := newClientCodec(t, "old", newKey(10))
	server := newServerCodec(t, "new", newKey(11), map[string][]byte{"old": newKey(10)})

	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{UserID: 1})
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
	client := newClientCodec(t, "kidA", newKey(12))
	ctx := context.Background()
	typedKey := xctx.NewTypedKey[PassingContext]("xctx")
	ctx = xctx.DefaultInjector[PassingContext](typedKey)(ctx, PassingContext{})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("X-Context") == "" {
		t.Fatal("header not set")
	}
}
