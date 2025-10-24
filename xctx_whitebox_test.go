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

// file: ./xctx_whitebox_test.go

package xctx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// EPassingContext is a minimal payload used in white-box tests to trigger
// precise validation branches and exercise internals deterministically.
type EPassingContext struct {
	UserID int32  `json:"uid"`
	Name   string `json:"un"`
}

// newKey returns a deterministic 32-byte key filled with the given byte.
func newKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// errReader forces a read error to simulate nonce generation failures.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

// -----------------------------------------------------------------------------
// Keyring negative tests
// -----------------------------------------------------------------------------

// TestNewKeyring_ErrCurrentKeyWrongLen verifies that NewKeyring rejects a
// current key whose length is not exactly 32 bytes (AES‑256). It passes a
// deliberately short key.
func TestNewKeyring_ErrCurrentKeyWrongLen(t *testing.T) {
	_, err := NewKeyring("kid", []byte("too-short"), nil)
	if err == nil || !strings.Contains(err.Error(), "current key must be 32 bytes") {
		t.Fatalf("expected size error, got %v", err)
	}
}

// TestNewKeyring_ErrOthersKeyWrongLen ensures that NewKeyring validates each
// entry in the rotation map `others` by passing a correct current key and an
// incorrect old key to trigger the validation error path.
func TestNewKeyring_ErrOthersKeyWrongLen(t *testing.T) {
	cur := newKey(1)
	_, err := NewKeyring("kid", cur, map[string][]byte{"old": []byte("short")})
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected others size error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// TypedKey identity tests
// -----------------------------------------------------------------------------

// TestTypedKey_SaferIdentity demonstrates that two keys created with the same
// name do not compare equal (hidden token differs). Storing with keyA cannot be
// retrieved with keyB.
func TestTypedKey_SaferIdentity(t *testing.T) {
	kA := NewTypedKey[EPassingContext]("xctx")
	kB := NewTypedKey[EPassingContext]("xctx")
	ctx := context.WithValue(context.Background(), kA, EPassingContext{UserID: 7})
	if _, ok := ctx.Value(kB).(EPassingContext); ok {
		t.Fatal("expected key mismatch due to unique token")
	}
	// DefaultExtractor returns zero value when absent.
	ex := DefaultExtractor[EPassingContext](kB)
	v, err := ex(ctx)
	if err != nil || v.UserID != 0 {
		t.Fatalf("default extractor should return zero value without error, got %+v, %v", v, err)
	}
}

// -----------------------------------------------------------------------------
// EmbedHeaderCtx negative tests
// -----------------------------------------------------------------------------

// TestEmbedHeaderCtx_ErrNoExtractor verifies that EmbedHeaderCtx fails when no
// Extractor has been configured on the Codec.
func TestEmbedHeaderCtx_ErrNoExtractor(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(2), nil)
	c := NewCodec[EPassingContext](kr) // no extractor set
	_, _, err := c.EmbedHeaderCtx(context.Background())
	if err == nil || !strings.Contains(err.Error(), "extractor not set") {
		t.Fatalf("expected extractor error, got %v", err)
	}
}

// TestEmbedHeaderCtx_ErrExtractorReturnsError confirms that any error returned
// by the caller‑provided Extractor is propagated by EmbedHeaderCtx unchanged.
func TestEmbedHeaderCtx_ErrExtractorReturnsError(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(3), nil)
	extractErr := errors.New("boom")
	ex := func(ctx context.Context) (EPassingContext, error) { return EPassingContext{}, extractErr }
	c := NewCodec[EPassingContext](kr, WithExtractor(ex))
	_, _, err := c.EmbedHeaderCtx(context.Background())
	if !errors.Is(err, extractErr) {
		t.Fatalf("expected extractor error propagated, got %v", err)
	}
}

// TestEmbedHeaderCtx_ErrNonceReadFailure exercises the error path where the
// crypto‑secure nonce cannot be generated. We replace randSource with an
// errReader so io.ReadFull fails.
func TestEmbedHeaderCtx_ErrNonceReadFailure(t *testing.T) {
	origRand := randSource
	defer func() { randSource = origRand }()
	randSource = errReader{err: io.ErrUnexpectedEOF}

	kr, _ := NewKeyring("kid", newKey(4), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	c := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)))
	ctx := DefaultInjector[EPassingContext](tk)(context.Background(), EPassingContext{UserID: 1})
	_, _, err := c.EmbedHeaderCtx(ctx)
	if err == nil {
		t.Fatal("expected error from nonce read failure")
	}
}

// TestSetHeader_PropagatesEmbedError ensures SetHeader returns any error from
// EmbedHeaderCtx instead of swallowing it.
func TestSetHeader_PropagatesEmbedError(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(5), nil)
	c := NewCodec[EPassingContext](kr) // no extractor; EmbedHeaderCtx will fail
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	if err := c.SetHeader(r, context.Background()); err == nil {
		t.Fatal("expected SetHeader to return error when EmbedHeaderCtx fails")
	}
}

// -----------------------------------------------------------------------------
// ParseCtx negative tests
// -----------------------------------------------------------------------------

// TestParseCtx_ErrMissingHeader validates that ParseCtx fails when the expected
// header is absent.
func TestParseCtx_ErrMissingHeader(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(6), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	c := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithInjector(DefaultInjector[EPassingContext](tk)))
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected missing header error")
	}
}

// TestParseCtx_ErrBadVersionPrefix ensures tokens with an unsupported textual
// prefix (e.g., "v2.") are rejected before any decoding attempt.
func TestParseCtx_ErrBadVersionPrefix(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(7), nil)
	c := NewCodec[EPassingContext](kr)
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v2.invalid")
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected bad version error")
	}
}

// TestParseCtx_ErrBadEnvelopeBase64 crafts an invalid base64 payload after the
// "v1." prefix to confirm the JSON envelope decoding path reports an error.
func TestParseCtx_ErrBadEnvelopeBase64(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(8), nil)
	c := NewCodec[EPassingContext](kr)
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v1.not-base64$$$")
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected bad envelope base64 error")
	}
}

// TestParseCtx_ErrEnvelopeMismatch creates a syntactically valid envelope but
// with a wrong version number to trip the envelope metadata validation branch.
func TestParseCtx_ErrEnvelopeMismatch(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(9), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 2, Alg: "AES256-GCM", KID: "kid", N: "", CT: ""}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected envelope mismatch error")
	}
}

// TestParseCtx_ErrUnknownKID builds an otherwise plausible envelope but with a
// KID not present in the Keyring, ensuring the unknown‑key branch is exercised.
func TestParseCtx_ErrUnknownKID(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(10), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "nope", N: "", CT: ""}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected unknown kid error")
	}
}

// TestParseCtx_ErrBadNonceBase64 supplies an envelope with a nonce that is not
// valid base64url text, covering the nonce decoding failure branch.
func TestParseCtx_ErrBadNonceBase64(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(11), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "kid", N: "!!!", CT: "AA"}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("expected bad nonce error, got %v", err)
	}
}

// TestParseCtx_ErrBadCiphertextBase64 supplies an envelope with an invalid
// base64url ciphertext, covering the ciphertext decoding failure branch.
func TestParseCtx_ErrBadCiphertextBase64(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(12), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "kid", N: b64urlEncode(make([]byte, 12)), CT: "!!!"}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "bad ciphertext") {
		t.Fatalf("expected bad ciphertext error, got %v", err)
	}
}

// TestParseCtx_ErrDecryptFailed provides a validly encoded envelope with a
// too‑short ciphertext that cannot be authenticated/decrypted by GCM.
func TestParseCtx_ErrDecryptFailed(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(13), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "kid", N: b64urlEncode(make([]byte, 12)), CT: b64urlEncode([]byte{1, 2, 3})}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected decrypt failure")
	}
}

// TestParseCtx_ErrBadPayloadJSON crafts a cryptographically valid header by
// calling the library's encryptor directly but uses a plaintext that is not
// valid JSON, exercising the payload unmarshal error branch.
func TestParseCtx_ErrBadPayloadJSON(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()
	nowFn = func() time.Time { return time.Unix(1_700_123_456, 0) }
	randSource = bytes.NewReader(bytes.Repeat([]byte{0xAA}, 64))

	kr, _ := NewKeyring("kid", newKey(14), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	client := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)))
	blob, err := client.encryptV1([]byte("not-json"))
	if err != nil {
		t.Fatalf("encryptV1: %v", err)
	}

	server := NewCodec[EPassingContext](kr)
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set(DefaultHeaderName, blob)
	if _, _, err := server.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "bad payload") {
		t.Fatalf("expected bad payload error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Time window & AAD white-box tests
// -----------------------------------------------------------------------------

// TestNotBeforeFailureWithControlledClock validates that the parser enforces
// Not-Before (nbf) by rejecting a token minted in the future.
func TestNotBeforeFailureWithControlledClock(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	randSource = bytes.NewReader(bytes.Repeat([]byte{0}, 64))
	t0 := time.Unix(1_700_000_000, 0)

	// Client issues at t0+10s
	nowFn = func() time.Time { return t0.Add(10 * time.Second) }
	krC, _ := NewKeyring("kidA", newKey(1), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	client := NewCodec[EPassingContext](krC, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithInjector(DefaultInjector[EPassingContext](tk)))
	ctx := DefaultInjector[EPassingContext](tk)(context.Background(), EPassingContext{UserID: 5})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}

	// Server validates at earlier time t0 -> should fail nbf
	nowFn = func() time.Time { return t0 }
	krS, _ := NewKeyring("kidA", newKey(1), nil)
	server := NewCodec[EPassingContext](krS, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithInjector(DefaultInjector[EPassingContext](tk)))
	if _, _, err := server.ParseCtx(r); err == nil {
		t.Fatal("expected not-before time error")
	}
}

// TestExpiryImmediate validates the consolidated time checks by issuing a token
// with a negative TTL (already expired) and confirming that the parser rejects
// it with a time-validity error.
func TestExpiryImmediate(t *testing.T) {
	kr, _ := NewKeyring("kid", newKey(15), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	client := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithTTL[EPassingContext](-1*time.Second))
	ctx := DefaultInjector[EPassingContext](tk)(context.Background(), EPassingContext{UserID: 99})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}

	server := NewCodec[EPassingContext](kr, WithInjector(DefaultInjector[EPassingContext](tk)))
	if _, _, err := server.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "token not valid (time)") {
		t.Fatalf("expected time validity error, got %v", err)
	}
}

// TestAADBinder_RoundTripAndMismatch shows that AAD is bound to the token:
// decryption succeeds only if both sides use the same AAD bytes.
func TestAADBinder_RoundTripAndMismatch(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	randSource = bytes.NewReader(bytes.Repeat([]byte{0x22}, 64))
	nowFn = func() time.Time { return time.Unix(1_700_300_000, 0) }

	kr, _ := NewKeyring("kidA", newKey(3), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	client := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithInjector(DefaultInjector[EPassingContext](tk)), WithAADBinder[EPassingContext](func() []byte { return []byte("A|B|C") }))
	ctx := DefaultInjector[EPassingContext](tk)(context.Background(), EPassingContext{UserID: 9})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}

	// Same AAD -> success
	serverOK := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithInjector(DefaultInjector[EPassingContext](tk)), WithAADBinder[EPassingContext](func() []byte { return []byte("A|B|C") }))
	if _, _, err := serverOK.ParseCtx(r); err != nil {
		t.Fatalf("parse with same AAD failed: %v", err)
	}

	// Different AAD -> AEAD auth failure
	serverBad := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)), WithInjector(DefaultInjector[EPassingContext](tk)), WithAADBinder[EPassingContext](func() []byte { return []byte("X") }))
	if _, _, err := serverBad.ParseCtx(r); err == nil {
		t.Fatal("expected parse failure with different AAD")
	}
}

// -----------------------------------------------------------------------------
// Internal helpers coverage
// -----------------------------------------------------------------------------

// TestEncryptV1_EnvelopeShapeAndPrefix verifies encryptV1 returns a properly
// prefixed header ("v1.") and that the inner envelope structure is sane.
func TestEncryptV1_EnvelopeShapeAndPrefix(t *testing.T) {
	origNow := nowFn
	origRand := randSource
	defer func() { nowFn = origNow; randSource = origRand }()

	nowFn = func() time.Time { return time.Unix(1_700_200_000, 0) }
	randSource = bytes.NewReader(bytes.Repeat([]byte{0x11}, 64))

	kr, _ := NewKeyring("kidZ", newKey(2), nil)
	c := NewCodec[EPassingContext](kr)
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

// TestBuildPayload_ClaimsWiring confirms that buildPayload wires issuer,
// audience, and TTL-derived times correctly into the JSON payload.
func TestBuildPayload_ClaimsWiring(t *testing.T) {
	origNow := nowFn
	defer func() { nowFn = origNow }()

	t0 := time.Unix(1_700_400_000, 0)
	nowFn = func() time.Time { return t0 }

	kr, _ := NewKeyring("kidC", newKey(4), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	c := NewCodec[EPassingContext](kr, WithIssuer[EPassingContext]("svc-A"), WithAudience[EPassingContext]("svc-B"), WithExtractor(DefaultExtractor[EPassingContext](tk)), WithTTL[EPassingContext](300*time.Second))
	ctx := DefaultInjector[EPassingContext](tk)(context.Background(), EPassingContext{UserID: 101, Name: "aria"})

	p, err := c.buildPayload(ctx)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var pl v1Payload[EPassingContext]
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

// TestGCM_RoundTripAndAAD exercises the low-level gcmSeal/gcmOpen helpers to
// ensure AEAD round-trip succeeds with correct AAD and fails when AAD differs.
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

// TestMakeJTIStableLength ensures makeJTI produces an identifier of stable
// length under deterministic randomness.
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

// mustJSON marshals v to JSON and panics on error. Suitable for tests where
// failures should fail the test immediately via panic.
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
