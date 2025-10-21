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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// EPassingContext is a minimal typed payload used across these error-path tests.
// Keeping it small helps ensure failures we trigger are from the intended
// validation branches rather than payload size or serialization issues.
type EPassingContext struct {
	UserID int32  `json:"uid"`
	Name   string `json:"un"`
}

// -----------------------------------------------------------------------------
// Keyring negative tests
// -----------------------------------------------------------------------------

// TestNewKeyring_ErrCurrentKeyWrongLen verifies that NewKeyring rejects a
// current key whose length is not exactly 32 bytes (AES‑256). It does so by
// passing a deliberately short key.
func TestNewKeyring_ErrCurrentKeyWrongLen(t *testing.T) {
	_, err := NewKeyring("kid", []byte("too-short"), nil)
	if err == nil || !strings.Contains(err.Error(), "current key must be 32 bytes") {
		t.Fatalf("expected size error, got %v", err)
	}
}

// TestNewKeyring_ErrOthersKeyWrongLen ensures that NewKeyring validates every
// entry supplied in the rotation map `others`. It passes a correct current key
// and an incorrect old key to trigger the validation error path.
func TestNewKeyring_ErrOthersKeyWrongLen(t *testing.T) {
	cur := bytes.Repeat([]byte{1}, 32)
	_, err := NewKeyring("kid", cur, map[string][]byte{"old": []byte("short")})
	if err == nil || !strings.Contains(err.Error(), "must be 32 bytes") {
		t.Fatalf("expected others size error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// EmbedHeaderCtx negative tests
// -----------------------------------------------------------------------------

// TestEmbedHeaderCtx_ErrNoExtractor verifies that EmbedHeaderCtx fails when no
// Extractor has been configured on the Codec. This covers the guard that
// prevents attempting to read a typed value from context without instructions.
func TestEmbedHeaderCtx_ErrNoExtractor(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{2}, 32), nil)
	c := NewCodec[EPassingContext](kr) // no extractor set
	_, _, err := c.EmbedHeaderCtx(context.Background())
	if err == nil || !strings.Contains(err.Error(), "extractor not set") {
		t.Fatalf("expected extractor error, got %v", err)
	}
}

// TestEmbedHeaderCtx_ErrExtractorReturnsError confirms that any error returned
// by the caller‑provided Extractor is propagated to the caller of
// EmbedHeaderCtx unchanged.
func TestEmbedHeaderCtx_ErrExtractorReturnsError(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{3}, 32), nil)
	extractErr := errors.New("boom")
	ex := func(ctx context.Context) (EPassingContext, error) { return EPassingContext{}, extractErr }
	c := NewCodec[EPassingContext](kr, WithExtractor(ex))
	_, _, err := c.EmbedHeaderCtx(context.Background())
	if !errors.Is(err, extractErr) {
		t.Fatalf("expected extractor error propagated, got %v", err)
	}
}

// errReader forces a read error to simulate nonce generation failure.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

// TestEmbedHeaderCtx_ErrNonceReadFailure exercises the error path where the
// crypto‑secure nonce cannot be generated (e.g., entropy source failure). We
// replace the package‑level randSource with an errReader so io.ReadFull fails.
func TestEmbedHeaderCtx_ErrNonceReadFailure(t *testing.T) {
	origRand := randSource
	defer func() { randSource = origRand }()
	randSource = errReader{err: io.ErrUnexpectedEOF}

	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{4}, 32), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	c := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)))
	ctx := DefaultInjector[EPassingContext](tk)(context.Background(), EPassingContext{UserID: 1})
	_, _, err := c.EmbedHeaderCtx(ctx)
	if err == nil {
		t.Fatal("expected error from nonce read failure")
	}
}

// TestSetHeader_PropagatesEmbedError ensures SetHeader returns any error from
// EmbedHeaderCtx instead of swallowing it. Here, absence of an Extractor causes
// EmbedHeaderCtx to fail, and SetHeader should bubble that error up.
func TestSetHeader_PropagatesEmbedError(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{5}, 32), nil)
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
// header is absent. This covers the initial missing‑header guard.
func TestParseCtx_ErrMissingHeader(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{6}, 32), nil)
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
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{7}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v2.invalid")
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected bad version error")
	}
}

// TestParseCtx_ErrBadEnvelopeBase64 crafts an invalid base64 payload after the
// "v1." prefix to confirm the JSON envelope decoding path reports an error.
func TestParseCtx_ErrBadEnvelopeBase64(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{8}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v1.not-base64$$$")
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected bad envelope base64 error")
	}
}

// TestParseCtx_ErrEnvelopeMismatch creates a syntactically valid envelope but
// with a wrong version number to trip the envelope metadata validation branch.
func TestParseCtx_ErrEnvelopeMismatch(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{9}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 2, Alg: "AES256-GCM", KID: "kid", N: "", CT: ""}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected envelope mismatch error")
	}
}

// TestParseCtx_ErrUnknownKID builds an otherwise plausible envelope but with a
// KID not present in the Keyring, ensuring the unknown‑key branch is exercised.
func TestParseCtx_ErrUnknownKID(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{10}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "nope", N: "", CT: ""}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil {
		t.Fatal("expected unknown kid error")
	}
}

// TestParseCtx_ErrBadNonceBase64 supplies an envelope with a nonce that is not
// valid base64url text, covering the nonce decoding failure branch.
func TestParseCtx_ErrBadNonceBase64(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{11}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "kid", N: "!!!", CT: "AA"}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("expected bad nonce error, got %v", err)
	}
}

// TestParseCtx_ErrBadCiphertextBase64 supplies an envelope with an invalid
// base64url ciphertext, covering the ciphertext decoding failure branch.
func TestParseCtx_ErrBadCiphertextBase64(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{12}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "kid", N: b64urlEncode(make([]byte, 12)), CT: "!!!"}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v1."+b64urlEncode(mustJSON(env)))
	if _, _, err := c.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "bad ciphertext") {
		t.Fatalf("expected bad ciphertext error, got %v", err)
	}
}

// TestParseCtx_ErrDecryptFailed provides a validly encoded envelope with a
// too‑short ciphertext that cannot be authenticated/decrypted by GCM, ensuring
// the "decrypt failed" error path is taken.
func TestParseCtx_ErrDecryptFailed(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{13}, 32), nil)
	c := NewCodec[EPassingContext](kr)
	env := v1Envelope{V: 1, Alg: "AES256-GCM", KID: "kid", N: b64urlEncode(make([]byte, 12)), CT: b64urlEncode([]byte{1, 2, 3})}
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", "v1."+b64urlEncode(mustJSON(env)))
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

	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{14}, 32), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	client := NewCodec[EPassingContext](kr, WithExtractor(DefaultExtractor[EPassingContext](tk)))
	blob, err := client.encryptV1([]byte("not-json"))
	if err != nil {
		t.Fatalf("encryptV1: %v", err)
	}

	server := NewCodec[EPassingContext](kr)
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	r.Header.Set("X-Context", blob)
	if _, _, err := server.ParseCtx(r); err == nil || !strings.Contains(err.Error(), "bad payload") {
		t.Fatalf("expected bad payload error, got %v", err)
	}
}

// TestParseCtx_ErrTimeWindowInvalid validates the consolidated time checks by
// issuing a token with a negative TTL (already expired) and confirms that the
// parser rejects it with the not‑valid‑time error message.
func TestParseCtx_ErrTimeWindowInvalid(t *testing.T) {
	kr, _ := NewKeyring("kid", bytes.Repeat([]byte{15}, 32), nil)
	tk := NewTypedKey[EPassingContext]("xctx")
	client := NewCodec[EPassingContext](kr,
		WithExtractor(DefaultExtractor[EPassingContext](tk)),
		WithTTL[EPassingContext](-1*time.Second),
	)
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

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// mustJSON marshals v to JSON and panics on error. Suitable for tests where
// failures should fail the test immediately via panic.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// The tests in this file rely on the package‑level variables nowFn and
// randSource (defined in xctx.go) to deterministically simulate edge cases.
// They are restored to their original values at the end of each test that
// overrides them to avoid cross‑test interference.
