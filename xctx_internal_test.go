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

package xctx

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// WPassingContext is a tiny payload type used for white-box tests where we need
// to poke at internals (nowFn, randSource, encryptV1, buildPayload, etc.).
type WPassingContext struct {
	UserID int32  `json:"uid"`
	Name   string `json:"un"`
}

// newKey returns a deterministic 32-byte key filled with the provided byte.
func newKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// -----------------------------------------------------------------------------
// TestNotBeforeFailureWithControlledClock
// -----------------------------------------------------------------------------
// Purpose:
//
//	Validate that the parser enforces the Not-Before (nbf) time by rejecting a
//	token minted “in the future”.
//
// How:
//  1. Freeze the client's clock to t0+10s so EmbedHeaderCtx creates a token
//     with iat/nbf= t0+10s.
//  2. Freeze the server's clock to t0 and attempt ParseCtx.
//  3. Expect an error mentioning time validity.
func TestNotBeforeFailureWithControlledClock(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	// Deterministic random to prevent flakes and make nonces predictable length.
	randSource = bytes.NewReader(bytes.Repeat([]byte{0}, 64))

	t0 := time.Unix(1_700_000_000, 0)

	// Client issues at t0+10s
	nowFn = func() time.Time { return t0.Add(10 * time.Second) }
	krC, _ := NewKeyring("kidA", newKey(1), nil)
	tk := NewTypedKey[WPassingContext]("xctx")
	client := NewCodec[WPassingContext](krC,
		WithExtractor(DefaultExtractor[WPassingContext](tk)),
		WithInjector(DefaultInjector[WPassingContext](tk)),
	)
	ctx := DefaultInjector[WPassingContext](tk)(context.Background(), WPassingContext{UserID: 5})
	r := httptest.NewRequest("GET", "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}

	// Server validates at earlier time t0 -> should fail nbf
	nowFn = func() time.Time { return t0 }
	krS, _ := NewKeyring("kidA", newKey(1), nil)
	server := NewCodec[WPassingContext](krS,
		WithExtractor(DefaultExtractor[WPassingContext](tk)),
		WithInjector(DefaultInjector[WPassingContext](tk)),
	)
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected not-before time error")
	}
}

// -----------------------------------------------------------------------------
// TestMakeJTIStableLength
// -----------------------------------------------------------------------------
// Purpose:
//
//	Ensure makeJTI produces an identifier of stable length (22 chars with the
//	current implementation), aiding logging and storage sizing.
//
// How:
//  1. Fix time and provide deterministic random bytes.
//  2. Call makeJTI and verify the exact length.
func TestMakeJTIStableLength(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	nowFn = func() time.Time { return time.Unix(1_700_123_456, 789_000_000) }
	randSource = bytes.NewReader(bytes.Repeat([]byte{0xAB}, 32))

	jti := makeJTI(nowFn())
	if len(jti) != 22 {
		t.Fatalf("unexpected jti length: %d (%q)", len(jti), jti)
	}
}

// -----------------------------------------------------------------------------
// TestEncryptV1_EnvelopeShapeAndPrefix
// -----------------------------------------------------------------------------
// Purpose:
//
//	Verify encryptV1 returns a properly prefixed header ("v1.") and that the
//	inner envelope structure is sane (version, alg, kid, 12-byte nonce, non-
//	empty ciphertext).
//
// How:
//  1. Freeze clock and random source for determinism.
//  2. Call encryptV1 with a small plaintext.
//  3. Strip the prefix, decode the envelope JSON, and assert fields.
func TestEncryptV1_EnvelopeShapeAndPrefix(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	nowFn = func() time.Time { return time.Unix(1_700_200_000, 0) }
	randSource = bytes.NewReader(bytes.Repeat([]byte{0x11}, 64))

	kr, _ := NewKeyring("kidZ", newKey(2), nil)
	c := NewCodec[WPassingContext](kr)
	blob, err := c.encryptV1([]byte("hello"))
	if err != nil {
		t.Fatalf("encryptV1: %v", err)
	}
	if got, want := blob[:3], "v1."; got != want {
		t.Fatalf("missing v1 prefix: %q", blob)
	}
	var env v1Envelope
	if err := json.Unmarshal(b64urlDecode(blob[3:]), &env); err != nil {
		t.Fatalf("unmarshal env: %v", err)
	}
	if env.V != 1 || env.Alg != "AES256-GCM" || env.KID != "kidZ" {
		t.Fatalf("bad env fields: %+v", env)
	}
	nonce, err := b64url(env.N)
	if err != nil || len(nonce) != 12 {
		t.Fatalf("bad nonce: %v len=%d", err, len(nonce))
	}
	ct, err := b64url(env.CT)
	if err != nil || len(ct) == 0 {
		t.Fatalf("bad ct: %v len=%d", err, len(ct))
	}
}

// -----------------------------------------------------------------------------
// TestAADBinder_RoundTripAndMismatch
// -----------------------------------------------------------------------------
// Purpose:
//
//	Demonstrate that Additional Authenticated Data (AAD) is bound to the token:
//	decryption succeeds only if both sides use the same AAD bytes; otherwise it
//	fails at the AEAD authentication step.
//
// How:
//  1. Client codec uses AAD binder returning "A|B|C" and sets the header.
//  2. Server with the SAME binder parses successfully.
//  3. Server with a DIFFERENT binder ("X") fails to parse the same header.
func TestAADBinder_RoundTripAndMismatch(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	randSource = bytes.NewReader(bytes.Repeat([]byte{0x22}, 64))
	nowFn = func() time.Time { return time.Unix(1_700_300_000, 0) }

	kr, _ := NewKeyring("kidA", newKey(3), nil)
	tk := NewTypedKey[WPassingContext]("xctx")
	client := NewCodec[WPassingContext](kr,
		WithExtractor(DefaultExtractor[WPassingContext](tk)),
		WithInjector(DefaultInjector[WPassingContext](tk)),
		WithAADBinder[WPassingContext](func() []byte { return []byte("A|B|C") }),
	)
	ctx := DefaultInjector[WPassingContext](tk)(context.Background(), WPassingContext{UserID: 9})
	r := httptest.NewRequest("GET", "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}

	// Same AAD -> success
	serverOK := NewCodec[WPassingContext](kr,
		WithExtractor(DefaultExtractor[WPassingContext](tk)),
		WithInjector(DefaultInjector[WPassingContext](tk)),
		WithAADBinder[WPassingContext](func() []byte { return []byte("A|B|C") }),
	)
	if _, _, err := serverOK.ParseCtx(r); err != nil {
		t.Fatalf("parse with same AAD failed: %v", err)
	}

	// Different AAD -> AEAD auth failure
	serverBad := NewCodec[WPassingContext](kr,
		WithExtractor(DefaultExtractor[WPassingContext](tk)),
		WithInjector(DefaultInjector[WPassingContext](tk)),
		WithAADBinder[WPassingContext](func() []byte { return []byte("X") }),
	)
	if _, _, err := serverBad.ParseCtx(r); err == nil {
		t.Fatal("expected parse failure with different AAD")
	}
}

// -----------------------------------------------------------------------------
// TestBuildPayload_ClaimsWiring
// -----------------------------------------------------------------------------
// Purpose:
//
//	Confirm that buildPayload wires issuer, audience, and TTL-derived times
//	correctly into the JSON payload.
//
// How:
//  1. Freeze time at t0 and set TTL=300s.
//  2. Put a typed struct in context and call buildPayload.
//  3. Unmarshal and verify Iss/Aud/Iat/Nbf/Exp are consistent with inputs.
func TestBuildPayload_ClaimsWiring(t *testing.T) {
	origNow := nowFn
	defer func() { nowFn = origNow }()

	t0 := time.Unix(1_700_400_000, 0)
	nowFn = func() time.Time { return t0 }

	kr, _ := NewKeyring("kidC", newKey(4), nil)
	tk := NewTypedKey[WPassingContext]("xctx")
	c := NewCodec[WPassingContext](kr,
		WithIssuer[WPassingContext]("svc-A"),
		WithAudience[WPassingContext]("svc-B"),
		WithExtractor(DefaultExtractor[WPassingContext](tk)),
		WithTTL[WPassingContext](300*time.Second),
	)
	ctx := DefaultInjector[WPassingContext](tk)(context.Background(), WPassingContext{UserID: 101, Name: "aria"})

	p, err := c.buildPayload(ctx)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var pl v1Payload[WPassingContext]
	if err := json.Unmarshal(p, &pl); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if pl.Iss != "svc-A" || pl.Aud != "svc-B" {
		t.Fatalf("iss/aud mismatch: %+v", pl)
	}
	if pl.Iat != t0.Unix() || pl.Nbf != t0.Unix() || pl.Exp != t0.Add(300*time.Second).Unix() {
		t.Fatalf("time claims wrong: %+v", pl)
	}
	if pl.Ctx.UserID != 101 || pl.Ctx.Name != "aria" {
		t.Fatalf("ctx payload wrong: %+v", pl.Ctx)
	}
	if got := len(pl.Jti); got == 0 {
		t.Fatal("jti should be non-empty")
	}
}

// -----------------------------------------------------------------------------
// TestGCM_RoundTripAndAAD
// -----------------------------------------------------------------------------
// Purpose:
//
//	Exercise the low-level gcmSeal/gcmOpen helpers directly to ensure AEAD
//	round-trip succeeds with the correct key/nonce/AAD and fails when AAD
//	differs.
//
// How:
//  1. Use a fixed key and nonce; seal plaintext with AAD "foo".
//  2. Open with the same AAD -> success; open with AAD "bar" -> failure.
func TestGCM_RoundTripAndAAD(t *testing.T) {
	key := newKey(7)
	nonce := bytes.Repeat([]byte{0x33}, 12)
	plain := []byte("payload")
	aad1 := []byte("foo")
	aad2 := []byte("bar")

	ct, err := gcmSeal(key, nonce, plain, aad1)
	if err != nil {
		t.Fatalf("gcmSeal: %v", err)
	}

	pt, err := gcmOpen(key, nonce, ct, aad1)
	if err != nil {
		t.Fatalf("gcmOpen same AAD: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("roundtrip mismatch: %q != %q", pt, plain)
	}

	if _, err := gcmOpen(key, nonce, ct, aad2); err == nil {
		t.Fatal("expected auth failure with different AAD")
	}
}
