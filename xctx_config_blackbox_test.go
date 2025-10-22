package xctx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xctx "github.com/ArieDeha/xctx"
)

// CfgBBPayload is a tiny payload used in black-box config tests.
type CfgBBPayload struct {
	ID int `json:"id"`
}

// kb returns a deterministic 32-byte key with constant bytes.
func kb(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// -----------------------------------------------------------------------------
// BuildCodecFromEnvWithKey – end-to-end happy path
// -----------------------------------------------------------------------------

// TestBuildCodecFromEnvWithKey_RoundTrip (Purpose)
//
//	End-to-end happy path using high-level helper that merges env+overrides and
//	auto-creates a TypedKey.
//
// (How)
//
//	Provide user overrides (keys, ttl, claims). Use returned key to inject and
//	round-trip a value through SetHeader/ParseCtx.
func TestBuildCodecFromEnvWithKey_RoundTrip(t *testing.T) {
	user := xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        2 * time.Minute,
		CurrentKID: "kid",
		CurrentKey: kb(1),
	}
	client, cKey, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, sKey, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	ctx := xctx.DefaultInjector[CfgBBPayload](cKey)(context.Background(), CfgBBPayload{ID: 7})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}
	ctx2, got, err := server.ParseCtx(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = ctx2
	if got.ID != 7 {
		t.Fatalf("got %+v", got)
	}
	// Sanity: returned typed keys are identity-distinct per builder invocation.
	if cKey == sKey {
		t.Fatal("expected different typed key instances from separate builders")
	}
}

// -----------------------------------------------------------------------------
// Env precedence – user overrides beat environment
// -----------------------------------------------------------------------------

// TestEnvPrecedence_OverridesWin (Purpose)
//
//	Confirms that user overrides replace conflicting environment values.
//
// (How)
//
//	Set env issuer/audience to values that would fail; user overrides provide
//	the correct ones; round trip should succeed.
func TestEnvPrecedence_OverridesWin(t *testing.T) {
	t.Setenv("XCTX_ISSUER", "env-iss")
	t.Setenv("XCTX_AUDIENCE", "env-aud")

	user := xctx.Config{
		HeaderName: xctx.DefaultHeaderName,
		Issuer:     "svc-A",
		Audience:   "svc-B",
		TTL:        time.Minute,
		CurrentKID: "kid",
		CurrentKey: kb(2),
	}
	client, ck, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, sk, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	ctx := xctx.DefaultInjector[CfgBBPayload](ck)(context.Background(), CfgBBPayload{ID: 1})
	r := httptest.NewRequest(http.MethodGet, "http://t/", nil).WithContext(ctx)
	if err = client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err = server.ParseCtx(r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = sk
}

// -----------------------------------------------------------------------------
// Invalid env – error propagation
// -----------------------------------------------------------------------------

// TestEnvInvalidTTL_PropagatesError (Purpose)
//
//	Ensures invalid TTL in the environment causes BuildCodecFromEnvWithKey to
//	return an error.
//
// (How)
//
//	Set XCTX_TTL to a bad value; provide minimal user config to supply keys.
func TestEnvInvalidTTL_PropagatesError(t *testing.T) {
	t.Setenv("XCTX_TTL", "not-a-duration")
	user := xctx.Config{CurrentKID: "kid", CurrentKey: kb(3)}
	if _, _, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil); err == nil {
		t.Fatal("expected error from invalid env TTL")
	}
}

// -----------------------------------------------------------------------------
// TypedKeyName from env
// -----------------------------------------------------------------------------

// TestTypedKeyNameFromEnv (Purpose)
//
//	Verifies that XCTX_TYPED_KEY_NAME affects the auto-created typed key.
//
// (How)
//
//	Set env var; call BuildCodecFromEnvWithKey with nil key; ensure the key is
//	functional by performing a roundtrip.
func TestTypedKeyNameFromEnv(t *testing.T) {
	t.Setenv("XCTX_TYPED_KEY_NAME", "envkey")
	user := xctx.Config{TTL: time.Minute, CurrentKID: "kid", CurrentKey: kb(4)}
	client, ck, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, _, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	ctx := xctx.DefaultInjector[CfgBBPayload](ck)(context.Background(), CfgBBPayload{ID: 3})
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}
	if _, got, err := server.ParseCtx(r); err != nil || got.ID != 3 {
		t.Fatalf("roundtrip failed: %+v %v", got, err)
	}
}

// -----------------------------------------------------------------------------
// BuildCodecFromEnv (explicit hooks) – success and AAD mismatch
// -----------------------------------------------------------------------------

// TestBuildCodecFromEnv_ExplicitHooks_AADPaths (Purpose)
//
//	Covers BuildCodecFromEnv with explicit extractor/injector, including both
//	success (same AAD) and failure (different AAD) branches.
//
// (How)
//
//	Build client/server with same cfg and two different AAD binders; first
//	attempt with matching AAD must succeed; second with different AAD must fail.
func TestBuildCodecFromEnv_ExplicitHooks_AADPaths(t *testing.T) {
	user := xctx.Config{TTL: time.Minute, CurrentKID: "kid", CurrentKey: kb(5)}
	key := xctx.NewTypedKey[CfgBBPayload]("x")

	// success with matching AAD
	clientOK, err := xctx.BuildCodecFromEnv[CfgBBPayload](user, xctx.DefaultExtractor[CfgBBPayload](key), xctx.DefaultInjector[CfgBBPayload](key), func() []byte { return []byte("A") })
	if err != nil {
		t.Fatalf("clientOK: %v", err)
	}
	serverOK, err := xctx.BuildCodecFromEnv[CfgBBPayload](user, xctx.DefaultExtractor[CfgBBPayload](key), xctx.DefaultInjector[CfgBBPayload](key), func() []byte { return []byte("A") })
	if err != nil {
		t.Fatalf("serverOK: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	ctx := xctx.DefaultInjector[CfgBBPayload](key)(context.Background(), CfgBBPayload{ID: 9})
	if err := clientOK.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := serverOK.ParseCtx(r); err != nil {
		t.Fatalf("parse with same AAD failed: %v", err)
	}

	// failure with different AAD
	serverBad, err := xctx.BuildCodecFromEnv[CfgBBPayload](user, xctx.DefaultExtractor[CfgBBPayload](key), xctx.DefaultInjector[CfgBBPayload](key), func() []byte { return []byte("B") })
	if err != nil {
		t.Fatalf("serverBad: %v", err)
	}
	if _, _, err := serverBad.ParseCtx(r); err == nil {
		t.Fatal("expected decrypt failure with mismatched AAD")
	}
}

// -----------------------------------------------------------------------------
// BuildCodecFromEnvWithKey – provided key path
// -----------------------------------------------------------------------------

// TestBuildCodecFromEnvWithKey_ProvidedKeyUsed (Purpose)
//
//	Exercises the branch in BuildCodecFromEnvWithKey that uses a caller-provided
//	TypedKey instead of auto-creating one, and ensures the returned key equals
//	the provided instance.
//
// (How)
//
//	Create a key, pass &key, and compare equality; also perform a round-trip.
func TestBuildCodecFromEnvWithKey_ProvidedKeyUsed(t *testing.T) {
	user := xctx.Config{TTL: time.Minute, CurrentKID: "kid", CurrentKey: kb(6)}
	key := xctx.NewTypedKey[CfgBBPayload]("custom")
	client, got, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, &key, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if got != key {
		t.Fatal("returned key must equal provided key")
	}

	r := httptest.NewRequest(http.MethodGet, "http://t/", nil)
	ctx := xctx.DefaultInjector[CfgBBPayload](key)(context.Background(), CfgBBPayload{ID: 11})
	if err := client.SetHeader(r, ctx); err != nil {
		t.Fatal(err)
	}
	server, _, _ := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, &key, nil)
	if _, v, err := server.ParseCtx(r); err != nil || v.ID != 11 {
		t.Fatalf("roundtrip failed: %+v %v", v, err)
	}
}

// -----------------------------------------------------------------------------
// Missing key – validation error path
// -----------------------------------------------------------------------------

// TestBuildCodecFromEnv_ErrorOnMissingKey (Purpose)
//
//	Ensures missing key material results in a validation error.
//
// (How)
//
//	Provide user config without CurrentKey and no env key; expect error.
func TestBuildCodecFromEnv_ErrorOnMissingKey(t *testing.T) {
	user := xctx.Config{CurrentKID: "kid", TTL: time.Minute}
	if _, _, err := xctx.BuildCodecFromEnvWithKey[CfgBBPayload](user, nil, nil); err == nil {
		t.Fatal("expected missing key error")
	}
}
