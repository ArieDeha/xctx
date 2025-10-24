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

// file: ./xctx_config_whitebox_test.go

package xctx

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

// CfgPayload is a tiny typed payload used by config white-box tests.
type CfgPayload struct {
	ID  int    `json:"id"`
	NAM string `json:"nm"`
}

// mkKey builds a deterministic 32-byte key filled with b.
func mkKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// TestLoadEnvConfig_AllFields (Purpose)
//
//	Ensures LoadEnvConfig reads and decodes all supported env vars, including
//	TTL, current key (hex/base64/raw supported generically by decodeKeyString),
//	other keys list, and typed key name.
//
// (How)
//
//	Set envs with t.Setenv; encode keys in different formats; call LoadEnvConfig
//	and assert parsed fields.
func TestLoadEnvConfig_AllFields(t *testing.T) {
	// Prepare encodings
	cur := mkKey(0xCA)
	curHex := hex.EncodeToString(cur)
	old := mkKey(0xEF)
	oldB64 := base64.StdEncoding.EncodeToString(old) // std b64 with padding

	t.Setenv("XCTX_HEADER_NAME", "X-Ctx")
	t.Setenv("XCTX_ISSUER", "env-iss")
	t.Setenv("XCTX_AUDIENCE", "env-aud")
	t.Setenv("XCTX_TTL", "2m30s")
	t.Setenv("XCTX_CURRENT_KID", "kid-env")
	t.Setenv("XCTX_CURRENT_KEY", curHex)       // hex
	t.Setenv("XCTX_OTHER_KEYS", "old="+oldB64) // base64
	t.Setenv("XCTX_TYPED_KEY_NAME", "envkey")

	cfg, err := LoadEnvConfig()
	if err != nil {
		t.Fatalf("LoadEnvConfig: %v", err)
	}

	if cfg.HeaderName != "X-Ctx" || cfg.Issuer != "env-iss" || cfg.Audience != "env-aud" {
		t.Fatalf("unexpected strings: %+v", cfg)
	}
	if cfg.TTL != 150*time.Second {
		t.Fatalf("ttl parsed wrong: %v", cfg.TTL)
	}
	if cfg.CurrentKID != "kid-env" {
		t.Fatalf("kid wrong: %s", cfg.CurrentKID)
	}
	if len(cfg.CurrentKey) != 32 || cfg.CurrentKey[0] != 0xCA {
		t.Fatalf("key decode wrong: %x", cfg.CurrentKey[:4])
	}
	if len(cfg.OtherKeys) != 1 || len(cfg.OtherKeys["old"]) != 32 || cfg.OtherKeys["old"][0] != 0xEF {
		t.Fatalf("others decode wrong: %#v", cfg.OtherKeys)
	}
	if cfg.TypedKeyName != "envkey" {
		t.Fatalf("typed key name wrong: %q", cfg.TypedKeyName)
	}
}

// TestLoadEnvConfig_InvalidTTL (Purpose)
//
//	Verifies invalid durations are rejected.
//
// (How)
//
//	Set XCTX_TTL to a non-duration string; expect error.
func TestLoadEnvConfig_InvalidTTL(t *testing.T) {
	t.Setenv("XCTX_TTL", "not-a-duration")
	if _, err := LoadEnvConfig(); err == nil {
		t.Fatal("expected TTL parse error")
	}
}

// TestLoadEnvConfig_InvalidCurrentKey (Purpose)
//
//	Verifies invalid current key encoding is rejected.
//
// (How)
//
//	Set XCTX_CURRENT_KEY to a short string; expect error.
func TestLoadEnvConfig_InvalidCurrentKey(t *testing.T) {
	t.Setenv("XCTX_CURRENT_KEY", "short")
	if _, err := LoadEnvConfig(); err == nil {
		t.Fatal("expected key decode error")
	}
}

// TestLoadEnvConfig_InvalidOtherKeys (Purpose)
//
//	Ensures malformed entries or bad lengths in XCTX_OTHER_KEYS are rejected.
//
// (How)
//
//	Provide a bad entry (no '='); expect error; then a bad-length key.
func TestLoadEnvConfig_InvalidOtherKeys(t *testing.T) {
	t.Setenv("XCTX_OTHER_KEYS", "novalue")
	if _, err := LoadEnvConfig(); err == nil {
		t.Fatal("expected bad kv error")
	}

	bad := base64.StdEncoding.EncodeToString([]byte("not-32-bytes"))
	t.Setenv("XCTX_OTHER_KEYS", "kid="+bad)
	if _, err := LoadEnvConfig(); err == nil {
		t.Fatal("expected bad length error")
	}
}

// TestMerge_WithDefaults_Validate (Purpose)
//
//	Exercises precedence (env→overrides), defaulting, and validation rules.
//
// (How)
//
//	Simulate env via struct (no env read), merge overrides, apply defaults,
//	then Validate. Also verify default HeaderName/TTL/TypedKeyName.
func TestMerge_WithDefaults_Validate(t *testing.T) {
	base := Config{}
	over := Config{Issuer: "u-iss", Audience: "u-aud", TTL: time.Minute, CurrentKID: "kid", CurrentKey: mkKey(1)}
	cfg := base.Merge(over).WithDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.HeaderName != DefaultHeaderName {
		t.Fatalf("default header wrong: %q", cfg.HeaderName)
	}
	if cfg.TypedKeyName != "xctx" {
		t.Fatalf("default typed key name wrong: %q", cfg.TypedKeyName)
	}
}

// TestValidate_Errors (Purpose)
//
//	Confirms Validate reports the expected error cases.
//
// (How)
//
//	Try missing kid, wrong key length, non-positive TTL.
func TestValidate_Errors(t *testing.T) {
	bad := Config{HeaderName: "X", TTL: time.Second, CurrentKID: "", CurrentKey: mkKey(2)}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected missing kid error")
	}

	bad = Config{HeaderName: "X", TTL: time.Second, CurrentKID: "kid", CurrentKey: []byte("short")}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected key length error")
	}

	bad = Config{HeaderName: "X", TTL: 0, CurrentKID: "kid", CurrentKey: mkKey(3)}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected ttl error")
	}
}

// TestBuildCodec_ExplicitHooks (Purpose)
//
//	Builds a codec with explicit extractor/injector and verifies an end-to-end
//	header round-trip using the same config.
//
// (How)
//
//	Use BuildCodec with a TypedKey-derived default hooks; SetHeader then ParseCtx
//	with another codec created from the same config.
func TestBuildCodec_ExplicitHooks(t *testing.T) {
	cfg := Config{HeaderName: DefaultHeaderName, TTL: time.Minute, CurrentKID: "kid", CurrentKey: mkKey(4)}.WithDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	tk := NewTypedKey[CfgPayload]("xctx")
	client, err := BuildCodec[CfgPayload](cfg, DefaultExtractor[CfgPayload](tk), DefaultInjector[CfgPayload](tk), nil)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	server, err := BuildCodec[CfgPayload](cfg, DefaultExtractor[CfgPayload](tk), DefaultInjector[CfgPayload](tk), nil)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}

	req, _ := httpNew()
	ctx := DefaultInjector[CfgPayload](tk)(context.Background(), CfgPayload{ID: 10, NAM: "a"})
	if err := client.SetHeader(req, ctx); err != nil {
		t.Fatalf("set header: %v", err)
	}
	_, got, err := server.ParseCtx(req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.ID != 10 || got.NAM != "a" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

// TestBuildCodecWithKey_AutoKeyNameDefault (Purpose)
//
//	Verifies BuildCodecWithKey auto-creates a TypedKey when nil is supplied and
//	that the returned key works with DefaultInjector/Extractor.
//
// (How)
//
//	Build both client and server with BuildCodecWithKey(nil). Use returned keys
//	for each side and ensure round-trip succeeds.
func TestBuildCodecWithKey_AutoKeyNameDefault(t *testing.T) {
	cfg := Config{TTL: time.Minute, CurrentKID: "kid", CurrentKey: mkKey(5)}.WithDefaults()

	client, cKey, err := BuildCodecWithKey[CfgPayload](cfg, nil, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, _, err := BuildCodecWithKey[CfgPayload](cfg, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	req, _ := httpNew()
	ctx := DefaultInjector[CfgPayload](cKey)(context.Background(), CfgPayload{ID: 1})
	if err := client.SetHeader(req, ctx); err != nil {
		t.Fatalf("set: %v", err)
	}
	ctx2, got, err := server.ParseCtx(req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = ctx2
	if got.ID != 1 {
		t.Fatalf("got %+v", got)
	}
}

// TestBuildCodecWithKey_AutoKeyNameFromConfig (Purpose)
//
//	Ensures TypedKeyName in Config is honored when auto-creating a key.
//
// (How)
//
//	Provide TypedKeyName="custom"; compare the unexported name via white-box
//	access and run a simple SetHeader/ParseCtx round-trip.
func TestBuildCodecWithKey_AutoKeyNameFromConfig(t *testing.T) {
	cfg := Config{TTL: time.Minute, CurrentKID: "kid", CurrentKey: mkKey(6), TypedKeyName: "custom"}.WithDefaults()
	codec, key, err := BuildCodecWithKey[CfgPayload](cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if key.name != "custom" {
		t.Fatalf("typed key name not honored: %q", key.name)
	}

	req, _ := httpNew()
	ctx := DefaultInjector[CfgPayload](key)(context.Background(), CfgPayload{ID: 2})
	if err := codec.SetHeader(req, ctx); err != nil {
		t.Fatalf("set: %v", err)
	}
	server, _, _ := BuildCodecWithKey[CfgPayload](cfg, &key, nil)
	if _, got, err := server.ParseCtx(req); err != nil || got.ID != 2 {
		t.Fatalf("roundtrip failed: %+v %v", got, err)
	}
}

// TestMergeEnv_Precedence (Purpose)
//
//	Confirms env values are loaded first but user overrides take precedence.
//
// (How)
//
//	Set env issuer/audience, then override with user values and observe merged
//	result.
func TestMergeEnv_Precedence(t *testing.T) {
	t.Setenv("XCTX_ISSUER", "env-iss")
	t.Setenv("XCTX_AUDIENCE", "env-aud")

	user := Config{Issuer: "user-iss", Audience: "user-aud", TTL: time.Minute, CurrentKID: "kid", CurrentKey: mkKey(7)}
	cfg, err := MergeEnv(user)
	if err != nil {
		t.Fatalf("mergeenv: %v", err)
	}
	if cfg.Issuer != "user-iss" || cfg.Audience != "user-aud" {
		t.Fatalf("precedence wrong: %+v", cfg)
	}
}

// TestBuildCodecFromEnvWithKey_ErrorOnMissingKey (Purpose)
//
//	Verifies that missing keys (neither env nor user provide) cause an error.
//
// (How)
//
//	Only set kid; omit key in env and user; expect error.
func TestBuildCodecFromEnvWithKey_ErrorOnMissingKey(t *testing.T) {
	t.Setenv("XCTX_CURRENT_KID", "kid")
	user := Config{TTL: time.Minute} // no key provided
	if _, _, err := BuildCodecFromEnvWithKey[CfgPayload](user, nil, nil); err == nil {
		t.Fatal("expected validation error for missing key")
	}
}

// httpNew creates a bare request; kept local to avoid importing net/http
// in too many places and to keep this file focused on config tests.
func httpNew() (*http.Request, error) {
	return http.NewRequestWithContext(context.Background(), http.MethodGet, "http://t/", nil)
}
