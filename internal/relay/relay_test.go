// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nmicic/deaddrop/internal/clock"
	"github.com/nmicic/deaddrop/internal/relay"
	"github.com/nmicic/deaddrop/internal/slot"
)

const (
	testWriteTokenStr = "test-write-token-32-bytes-long!!"
	testMaxBlobBytes  = 1024
	testClockYYYY     = 2026
	testClockMM       = time.January
	testClockDD       = 15
	testClockHH       = 12
	testClockMin      = 30
)

var testWriteTokenHex = hex.EncodeToString([]byte(testWriteTokenStr))

func testDeploySecret() []byte { return bytes.Repeat([]byte{0x01}, 32) }

func testStartTime() time.Time {
	return time.Date(testClockYYYY, testClockMM, testClockDD, testClockHH, testClockMin, 0, 0, time.UTC)
}

// newTestEnv sets up a Handler over an httptest.Server with a fixed
// FakeClock, deterministic deploy secret + write token, and no store
// cap / semaphore gate (backwards-compat default for tests 1-34 that
// predate the later capacity tests).
func newTestEnv(t *testing.T) (*relay.Store, *httptest.Server, *clock.FakeClock) {
	t.Helper()
	return newTestEnvWithCap(t, 0, 0, nil)
}

// newTestEnvWithCap is newTestEnv with capacity knobs exposed:
// maxStoreBytes drives the store total-capacity cap (0 = off),
// maxConcurrentGets drives the semaphore gate (0 = off), and
// getHook is the handler's GetHook injection point (nil for most
// tests; test 35 uses it to hold a semaphore slot so a second GET
// can observe the full state).
func newTestEnvWithCap(t *testing.T, maxStoreBytes int64, maxConcurrentGets int, getHook func()) (
	*relay.Store, *httptest.Server, *clock.FakeClock,
) {
	t.Helper()
	fc := clock.NewFakeClock(testStartTime())
	st := relay.NewStore(fc, maxStoreBytes)
	h := relay.NewHandler(relay.Config{
		Store:             st,
		DeploySecret:      testDeploySecret(),
		WriteToken:        []byte(testWriteTokenStr),
		MaxBlobBytes:      testMaxBlobBytes,
		MaxConcurrentGets: maxConcurrentGets,
		Clock:             fc,
		GetHook:           getHook,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return st, srv, fc
}

// testSlotPath returns `/{svc_id_hex}/{slot_id_hex}` where svc_id is
// derived from the given timestamp and slot_id is a deterministic
// 16-byte value.
func testSlotPath(t *testing.T, ts time.Time) string {
	t.Helper()
	h := uint64(ts.Unix()) / 3600
	svcID, err := slot.ServiceID(testDeploySecret(), h)
	if err != nil {
		t.Fatalf("ServiceID: %v", err)
	}
	slotID := bytes.Repeat([]byte{0xAA}, 16)
	return "/" + hex.EncodeToString(svcID) + "/" + hex.EncodeToString(slotID)
}

// postWithToken issues a POST to path and returns the response. The
// write token is attached when token != "".
func postWithToken(t *testing.T, srv *httptest.Server, path string, body []byte, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("X-DeadDrop-Write", token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	return resp
}

func doGet(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	return resp
}

func readAllAndClose(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

// 1. TestPost_HappyPath.
func TestPost_HappyPath(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	resp := postWithToken(t, srv, path, []byte("opaque-ciphertext"), testWriteTokenHex)
	body := readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Fatalf("POST body must be empty, got %d bytes", len(body))
	}
}

// 2. TestPost_Get_RoundTrip — POST 100 bytes, GET back, assert headers.
func TestPost_Get_RoundTrip(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	payload := bytes.Repeat([]byte{0x7e}, 100)

	post := postWithToken(t, srv, path, payload, testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}

	getResp := doGet(t, srv, path)
	body := readAllAndClose(t, getResp)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getResp.StatusCode)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("GET body mismatch: got %d bytes, want %d", len(body), len(payload))
	}
	if got := getResp.Header.Get("X-DeadDrop-Reads-Left"); got != "0" {
		t.Fatalf("X-DeadDrop-Reads-Left = %q, want \"0\"", got)
	}
	if ct := getResp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", ct)
	}
}

// 3. TestPost_MissingWriteToken — absent header → 401.
func TestPost_MissingWriteToken(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	resp := postWithToken(t, srv, path, []byte("x"), "") // no header
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// 4. TestPost_WrongWriteToken.
func TestPost_WrongWriteToken(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	resp := postWithToken(t, srv, path, []byte("x"), "not-the-right-token")
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// 5. TestPost_InvalidServiceID — svc_id that matches neither hour → 404.
func TestPost_InvalidServiceID(t *testing.T) {
	_, srv, _ := newTestEnv(t)
	// Pick a service_id derived from an hour far in the future so it
	// matches neither the current nor the previous hour on the relay.
	farFuture := testStartTime().Add(240 * time.Hour)
	badPath := testSlotPath(t, farFuture)
	resp := postWithToken(t, srv, badPath, []byte("x"), testWriteTokenHex)
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// 6. TestPost_PreviousHourServiceID — write-side hour tolerance.
func TestPost_PreviousHourServiceID(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	// svc_id derived from the hour-before the relay's current time.
	prev := fc.Now().Add(-1 * time.Hour)
	path := testSlotPath(t, prev)
	resp := postWithToken(t, srv, path, []byte("x"), testWriteTokenHex)
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (previous-hour tolerance)", resp.StatusCode)
	}
}

// 7. TestPost_DuplicateSlot — first 201, second 409 empty body.
func TestPost_DuplicateSlot(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	first := postWithToken(t, srv, path, []byte("A"), testWriteTokenHex)
	_ = readAllAndClose(t, first)
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first status = %d, want 201", first.StatusCode)
	}

	second := postWithToken(t, srv, path, []byte("B"), testWriteTokenHex)
	secondBody := readAllAndClose(t, second)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", second.StatusCode)
	}
	if len(secondBody) != 0 {
		t.Fatalf("409 body must be empty, got %d bytes", len(secondBody))
	}
}

// 8. TestPost_OversizedBody — body > cap → 413 empty body.
func TestPost_OversizedBody(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	big := bytes.Repeat([]byte{0x01}, testMaxBlobBytes+1)
	resp := postWithToken(t, srv, path, big, testWriteTokenHex)
	body := readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Fatalf("413 body must be empty, got %d bytes", len(body))
	}
}

// 9. TestPost_EmptyBody — empty → 413 empty body.
func TestPost_EmptyBody(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	resp := postWithToken(t, srv, path, []byte{}, testWriteTokenHex)
	body := readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Fatalf("413 body must be empty, got %d bytes", len(body))
	}
}

// 10. TestGet_NotFound — path never POSTed → 404.
func TestGet_NotFound(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	resp := doGet(t, srv, path)
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// 11. TestGet_OneShot_SingleRead.
func TestGet_OneShot_SingleRead(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	payload := []byte("single-read-payload")

	post := postWithToken(t, srv, path, payload, testWriteTokenHex)
	_ = readAllAndClose(t, post)

	first := doGet(t, srv, path)
	firstBody := readAllAndClose(t, first)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first GET status = %d, want 200", first.StatusCode)
	}
	if !bytes.Equal(firstBody, payload) {
		t.Fatalf("first GET body mismatch")
	}

	second := doGet(t, srv, path)
	_ = readAllAndClose(t, second)
	if second.StatusCode != http.StatusNotFound {
		t.Fatalf("second GET status = %d, want 404", second.StatusCode)
	}
}

// 12. TestGet_MultiRead — reads=3, expect 2/1/0 on three GETs then 404.
func TestGet_MultiRead(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now()) + "?reads=3"
	postPath := testSlotPath(t, fc.Now())
	payload := []byte("multi-read")

	post := postWithToken(t, srv, path, payload, testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}

	for i, want := range []string{"2", "1", "0"} {
		resp := doGet(t, srv, postPath)
		body := readAllAndClose(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %d status = %d, want 200", i+1, resp.StatusCode)
		}
		if !bytes.Equal(body, payload) {
			t.Fatalf("GET %d body mismatch", i+1)
		}
		if got := resp.Header.Get("X-DeadDrop-Reads-Left"); got != want {
			t.Fatalf("GET %d X-DeadDrop-Reads-Left = %q, want %q", i+1, got, want)
		}
	}

	fourth := doGet(t, srv, postPath)
	_ = readAllAndClose(t, fourth)
	if fourth.StatusCode != http.StatusNotFound {
		t.Fatalf("fourth GET status = %d, want 404", fourth.StatusCode)
	}
}

// 13. TestGet_Race_OneShot — canonical AC-RACE: 100 parallel GETs, exactly one 200.
func TestGet_Race_OneShot(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	payload := bytes.Repeat([]byte{0x5c}, 64)

	post := postWithToken(t, srv, path, payload, testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}

	const N = 100
	type result struct {
		status int
		body   []byte
	}
	results := make([]result, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			resp, err := srv.Client().Get(srv.URL + path)
			if err != nil {
				results[i] = result{status: -1}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results[i] = result{status: resp.StatusCode, body: body}
		}()
	}
	wg.Wait()

	var ok200, not404, other int
	for _, r := range results {
		switch r.status {
		case http.StatusOK:
			ok200++
			if !bytes.Equal(r.body, payload) {
				t.Fatalf("200 body mismatch")
			}
		case http.StatusNotFound:
			not404++
			if len(r.body) != 0 {
				t.Fatalf("404 body must be empty, got %d bytes", len(r.body))
			}
		default:
			other++
		}
	}
	if ok200 != 1 {
		t.Fatalf("expected exactly 1 × 200, got %d", ok200)
	}
	if not404 != N-1 {
		t.Fatalf("expected %d × 404, got %d", N-1, not404)
	}
	if other != 0 {
		t.Fatalf("expected 0 other statuses, got %d", other)
	}
}

// 14. TestHead_Returns404 — HEAD on a valid slot → uniform 404.
func TestHead_Returns404(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	post := postWithToken(t, srv, path, []byte("payload"), testWriteTokenHex)
	_ = readAllAndClose(t, post)

	req, err := http.NewRequest(http.MethodHead, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest HEAD: %v", err)
	}
	headResp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	_ = readAllAndClose(t, headResp)
	if headResp.StatusCode != http.StatusNotFound {
		t.Fatalf("HEAD status = %d, want 404", headResp.StatusCode)
	}

	// Byte-identity with a GET on a never-POSTed path: same Content-Type
	// header and same status. (Full byte-identity across 5 classes is
	// verified elsewhere; here we just cross-check one pair.)
	otherSlot := "/" + hex.EncodeToString(bytes.Repeat([]byte{0xBB}, 16)) +
		"/" + hex.EncodeToString(bytes.Repeat([]byte{0xCC}, 16))
	nxResp := doGet(t, srv, otherSlot)
	_ = readAllAndClose(t, nxResp)
	if nxResp.StatusCode != headResp.StatusCode {
		t.Fatalf("HEAD-valid-slot vs GET-unknown-slot status differ: %d vs %d",
			headResp.StatusCode, nxResp.StatusCode)
	}
	if headResp.Header.Get("Content-Type") != nxResp.Header.Get("Content-Type") {
		t.Fatalf("Content-Type differ")
	}
}

// 15. TestUnknownMethod — PUT → 404, DELETE → 404.
func TestUnknownMethod(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest %s: %v", method, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_ = readAllAndClose(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", method, resp.StatusCode)
		}
	}
}

// 16. TestGet_Expired — ttl=60, advance 61s, GET → 404, store empty.
func TestGet_Expired(t *testing.T) {
	st, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now()) + "?ttl=60"
	getPath := testSlotPath(t, fc.Now())

	post := postWithToken(t, srv, path, []byte("ephemeral"), testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}
	if st.Len() != 1 {
		t.Fatalf("Len = %d, want 1", st.Len())
	}

	fc.Advance(61 * time.Second)

	resp := doGet(t, srv, getPath)
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET status = %d, want 404 (expired)", resp.StatusCode)
	}
	if st.Len() != 0 {
		t.Fatalf("Len after expired-GET = %d, want 0", st.Len())
	}
	if st.StoreBytes() != 0 {
		t.Fatalf("StoreBytes after expired-GET = %d, want 0", st.StoreBytes())
	}
}

// 17. TestBadPath_TooFewSegments — `/onlyone` → 404.
func TestBadPath_TooFewSegments(t *testing.T) {
	_, srv, _ := newTestEnv(t)
	resp := doGet(t, srv, "/onlyone")
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// 18. TestBadPath_NonHex — non-hex segments → 404.
func TestBadPath_NonHex(t *testing.T) {
	_, srv, _ := newTestEnv(t)
	// Use 32-char segments to pass the length gate, but non-hex so
	// hex.DecodeString rejects. Avoid '?' which starts a query string.
	bad := "/" + strings.Repeat("z", 32) + "/" + strings.Repeat("z", 32)
	resp := doGet(t, srv, bad)
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// 19. TestBadPath_WrongLength — too-short hex segments → 404.
func TestBadPath_WrongLength(t *testing.T) {
	_, srv, _ := newTestEnv(t)
	resp := doGet(t, srv, "/abc123/def456")
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// 20. TestStoreBytes_Tracking.
func TestStoreBytes_Tracking(t *testing.T) {
	st, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	payload := bytes.Repeat([]byte{0x22}, 100)
	post := postWithToken(t, srv, path, payload, testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}
	if st.Len() != 1 {
		t.Fatalf("Len = %d, want 1", st.Len())
	}
	if st.StoreBytes() != 100 {
		t.Fatalf("StoreBytes = %d, want 100", st.StoreBytes())
	}

	getResp := doGet(t, srv, path)
	_ = readAllAndClose(t, getResp)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getResp.StatusCode)
	}
	if st.Len() != 0 {
		t.Fatalf("Len after consume = %d, want 0", st.Len())
	}
	if st.StoreBytes() != 0 {
		t.Fatalf("StoreBytes after consume = %d, want 0", st.StoreBytes())
	}
}

// 21. TestGet_ContentType.
func TestGet_ContentType(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	post := postWithToken(t, srv, path, []byte("payload"), testWriteTokenHex)
	_ = readAllAndClose(t, post)

	resp := doGet(t, srv, path)
	_ = readAllAndClose(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", ct)
	}
}

// ---------------------------------------------------------------------------
// Tests 22-34: uniform-404 5-class, DELETE, GC.
// ---------------------------------------------------------------------------

// postWithTokenAndHash is postWithToken + an optional
// X-DeadDrop-Delete-Hash header. deleteHashHex is the hex-encoded
// SHA-256 digest the relay will associate with the slot; empty
// string disables DELETE for this slot.
func postWithTokenAndHash(t *testing.T, srv *httptest.Server, path string, body []byte, token, deleteHashHex string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("X-DeadDrop-Write", token)
	}
	if deleteHashHex != "" {
		req.Header.Set("X-DeadDrop-Delete-Hash", deleteHashHex)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	return resp
}

// doDelete issues DELETE with the given X-DeadDrop-Delete-Token value
// (empty string omits the header).
func doDelete(t *testing.T, srv *httptest.Server, path, tokenHex string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if tokenHex != "" {
		req.Header.Set("X-DeadDrop-Delete-Token", tokenHex)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	return resp
}

// resp404 captures the fields asserted identical across the
// five 404 failure classes (D-14 / AC-404-*).
type resp404 struct {
	class         string
	status        int
	contentType   string
	contentLength string
	body          []byte
	xErrorKeys    []string
}

func snapshot404(t *testing.T, class string, resp *http.Response) resp404 {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read body: %v", class, err)
	}
	var xErr []string
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-error-") {
			xErr = append(xErr, k)
		}
	}
	return resp404{
		class:         class,
		status:        resp.StatusCode,
		contentType:   resp.Header.Get("Content-Type"),
		contentLength: resp.Header.Get("Content-Length"),
		body:          body,
		xErrorKeys:    xErr,
	}
}

// 22. TestUniform404_FiveClasses — canonical AC-404 test. Collect the
// 404 response for each of the five classes and assert byte-identical
// (same Content-Type, same Content-Length, empty body, no X-Error-*).
func TestUniform404_FiveClasses(t *testing.T) {
	collect := make([]resp404, 0, 5)

	// AC-404-WRONGSVC: POST under svc_A + slot_X, GET under svc_B + slot_X.
	// Lookup in the map misses because the storeKey svc component differs.
	{
		_, srv, fc := newTestEnv(t)
		postPath := testSlotPath(t, fc.Now())
		post := postWithToken(t, srv, postPath, []byte("wrongsvc"), testWriteTokenHex)
		_ = readAllAndClose(t, post)

		// Derive a svc_id from an hour the store doesn't have; keep the
		// slot_id bytes identical to the POST path so only svc differs.
		otherHour := fc.Now().Add(10 * time.Hour)
		otherSvc, err := slot.ServiceID(testDeploySecret(), uint64(otherHour.Unix())/3600)
		if err != nil {
			t.Fatalf("ServiceID: %v", err)
		}
		slotID := bytes.Repeat([]byte{0xAA}, 16)
		wrongPath := "/" + hex.EncodeToString(otherSvc) + "/" + hex.EncodeToString(slotID)
		resp := doGet(t, srv, wrongPath)
		collect = append(collect, snapshot404(t, "WRONGSVC", resp))
	}

	// AC-404-NOSLOT: GET a valid-format path that was never POSTed.
	{
		_, srv, fc := newTestEnv(t)
		resp := doGet(t, srv, testSlotPath(t, fc.Now()))
		collect = append(collect, snapshot404(t, "NOSLOT", resp))
	}

	// AC-404-EXPIRED: POST with ttl=1, advance 2s, GET → 404 (expired).
	{
		_, srv, fc := newTestEnv(t)
		path := testSlotPath(t, fc.Now())
		post := postWithToken(t, srv, path+"?ttl=1", []byte("expired"), testWriteTokenHex)
		_ = readAllAndClose(t, post)
		fc.Advance(2 * time.Second)
		resp := doGet(t, srv, path)
		collect = append(collect, snapshot404(t, "EXPIRED", resp))
	}

	// AC-404-EXHAUSTED: POST reads=1, GET (drains), GET again → 404.
	{
		_, srv, fc := newTestEnv(t)
		path := testSlotPath(t, fc.Now())
		post := postWithToken(t, srv, path, []byte("exhausted"), testWriteTokenHex)
		_ = readAllAndClose(t, post)
		first := doGet(t, srv, path)
		_ = readAllAndClose(t, first)
		if first.StatusCode != http.StatusOK {
			t.Fatalf("EXHAUSTED first GET: want 200, got %d", first.StatusCode)
		}
		resp := doGet(t, srv, path)
		collect = append(collect, snapshot404(t, "EXHAUSTED", resp))
	}

	// AC-404-WRONGTOKEN: POST with delete-hash, DELETE with wrong token → 404.
	{
		_, srv, fc := newTestEnv(t)
		path := testSlotPath(t, fc.Now())
		token := bytes.Repeat([]byte{0x42}, 32)
		hash := sha256.Sum256(token)
		post := postWithTokenAndHash(t, srv, path, []byte("wrongtoken"),
			testWriteTokenHex, hex.EncodeToString(hash[:]))
		_ = readAllAndClose(t, post)
		wrongToken := bytes.Repeat([]byte{0x99}, 32)
		resp := doDelete(t, srv, path, hex.EncodeToString(wrongToken))
		collect = append(collect, snapshot404(t, "WRONGTOKEN", resp))
	}

	if len(collect) != 5 {
		t.Fatalf("expected 5 snapshots, got %d", len(collect))
	}

	ref := collect[0]
	if ref.status != http.StatusNotFound {
		t.Fatalf("%s status = %d, want 404", ref.class, ref.status)
	}
	if len(ref.body) != 0 {
		t.Fatalf("%s body must be empty, got %d bytes", ref.class, len(ref.body))
	}
	if len(ref.xErrorKeys) != 0 {
		t.Fatalf("%s unexpected X-Error-* headers: %v", ref.class, ref.xErrorKeys)
	}
	for _, s := range collect[1:] {
		if s.status != ref.status {
			t.Errorf("%s status = %d, want %d (same as %s)", s.class, s.status, ref.status, ref.class)
		}
		if s.contentType != ref.contentType {
			t.Errorf("%s Content-Type = %q, want %q (same as %s)",
				s.class, s.contentType, ref.contentType, ref.class)
		}
		if s.contentLength != ref.contentLength {
			t.Errorf("%s Content-Length = %q, want %q (same as %s)",
				s.class, s.contentLength, ref.contentLength, ref.class)
		}
		if !bytes.Equal(s.body, ref.body) {
			t.Errorf("%s body differs from %s", s.class, ref.class)
		}
		if len(s.xErrorKeys) != 0 {
			t.Errorf("%s unexpected X-Error-* headers: %v", s.class, s.xErrorKeys)
		}
	}
}

// 23. TestDelete_HappyPath — POST with delete-hash, DELETE with
// correct token → 204 and slot gone.
func TestDelete_HappyPath(t *testing.T) {
	st, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	token := bytes.Repeat([]byte{0xA1}, 32)
	hash := sha256.Sum256(token)

	post := postWithTokenAndHash(t, srv, path, []byte("to-be-deleted"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST: status = %d, want 201", post.StatusCode)
	}

	del := doDelete(t, srv, path, hex.EncodeToString(token))
	body := readAllAndClose(t, del)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", del.StatusCode)
	}
	if len(body) != 0 {
		t.Fatalf("204 body must be empty, got %d bytes", len(body))
	}

	get := doGet(t, srv, path)
	_ = readAllAndClose(t, get)
	if get.StatusCode != http.StatusNotFound {
		t.Fatalf("post-DELETE GET status = %d, want 404", get.StatusCode)
	}
	if st.Len() != 0 {
		t.Fatalf("Len = %d, want 0", st.Len())
	}
	if st.StoreBytes() != 0 {
		t.Fatalf("StoreBytes = %d, want 0", st.StoreBytes())
	}
}

// 24. TestDelete_WrongToken — DELETE with wrong token → 404; slot preserved.
func TestDelete_WrongToken(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	right := bytes.Repeat([]byte{0xB2}, 32)
	hash := sha256.Sum256(right)

	post := postWithTokenAndHash(t, srv, path, []byte("kept"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)

	wrong := bytes.Repeat([]byte{0xC3}, 32)
	del := doDelete(t, srv, path, hex.EncodeToString(wrong))
	_ = readAllAndClose(t, del)
	if del.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE (wrong token) status = %d, want 404", del.StatusCode)
	}

	get := doGet(t, srv, path)
	body := readAllAndClose(t, get)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET after wrong-token DELETE: status = %d, want 200", get.StatusCode)
	}
	if !bytes.Equal(body, []byte("kept")) {
		t.Fatalf("GET body mismatch after wrong-token DELETE")
	}
}

// 25. TestDelete_NoHashRegistered — POST without delete-hash; any
// DELETE attempt → 404, slot still GETtable.
func TestDelete_NoHashRegistered(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	post := postWithToken(t, srv, path, []byte("nohash"), testWriteTokenHex)
	_ = readAllAndClose(t, post)

	anyToken := bytes.Repeat([]byte{0x55}, 32)
	del := doDelete(t, srv, path, hex.EncodeToString(anyToken))
	_ = readAllAndClose(t, del)
	if del.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE (no hash registered) status = %d, want 404", del.StatusCode)
	}

	get := doGet(t, srv, path)
	body := readAllAndClose(t, get)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET after no-hash DELETE: status = %d, want 200", get.StatusCode)
	}
	if !bytes.Equal(body, []byte("nohash")) {
		t.Fatalf("GET body mismatch")
	}
}

// 26. TestDelete_MissingTokenHeader — DELETE without the token
// header → 404 (indistinguishable from not-found).
func TestDelete_MissingTokenHeader(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	token := bytes.Repeat([]byte{0x77}, 32)
	hash := sha256.Sum256(token)

	post := postWithTokenAndHash(t, srv, path, []byte("x"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)

	del := doDelete(t, srv, path, "")
	_ = readAllAndClose(t, del)
	if del.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE (missing token) status = %d, want 404", del.StatusCode)
	}
}

// 27. TestDelete_InvalidHexToken — DELETE with non-hex token header → 404.
func TestDelete_InvalidHexToken(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	token := bytes.Repeat([]byte{0x11}, 32)
	hash := sha256.Sum256(token)

	post := postWithTokenAndHash(t, srv, path, []byte("x"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)

	del := doDelete(t, srv, path, "not-valid-hex!!!")
	_ = readAllAndClose(t, del)
	if del.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE (non-hex token) status = %d, want 404", del.StatusCode)
	}
}

// 28. TestDelete_ExpiredSlot — DELETE on expired slot → 404.
func TestDelete_ExpiredSlot(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	token := bytes.Repeat([]byte{0x88}, 32)
	hash := sha256.Sum256(token)

	post := postWithTokenAndHash(t, srv, path+"?ttl=1", []byte("exp"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)

	fc.Advance(2 * time.Second)

	del := doDelete(t, srv, path, hex.EncodeToString(token))
	_ = readAllAndClose(t, del)
	if del.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE (expired) status = %d, want 404", del.StatusCode)
	}
}

// 29. TestPost_WithDeleteHash — POST carrying a valid 64-hex-char
// X-DeadDrop-Delete-Hash → 201.
func TestPost_WithDeleteHash(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	token := bytes.Repeat([]byte{0x33}, 32)
	hash := sha256.Sum256(token)

	post := postWithTokenAndHash(t, srv, path, []byte("ok"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}
}

// 30. TestPost_InvalidDeleteHash — malformed hash header → 400.
func TestPost_InvalidDeleteHash(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())

	cases := []struct {
		name string
		hex  string
	}{
		{"non-hex", "not-valid-hex!!" + strings.Repeat("0", 48)},
		{"wrong-length-short", strings.Repeat("aa", 16)},
		{"wrong-length-long", strings.Repeat("aa", 48)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			post := postWithTokenAndHash(t, srv, path, []byte("body"),
				testWriteTokenHex, c.hex)
			_ = readAllAndClose(t, post)
			if post.StatusCode != http.StatusBadRequest {
				t.Fatalf("POST (%s) status = %d, want 400", c.name, post.StatusCode)
			}
		})
	}
}

// 31. TestGC_SweepsExpired — two ttl=5 slots, advance 6s, Sweep
// returns 2 and clears the store.
func TestGC_SweepsExpired(t *testing.T) {
	st, srv, fc := newTestEnv(t)

	// Two distinct slot_ids so Put does not 409 on duplicate.
	basePath := testSlotPath(t, fc.Now())
	post1 := postWithToken(t, srv, basePath+"?ttl=5", []byte("one"), testWriteTokenHex)
	_ = readAllAndClose(t, post1)

	otherSlot := bytes.Repeat([]byte{0xBB}, 16)
	svcHex := strings.Split(basePath, "/")[1]
	path2 := "/" + svcHex + "/" + hex.EncodeToString(otherSlot)
	post2 := postWithToken(t, srv, path2+"?ttl=5", []byte("two"), testWriteTokenHex)
	_ = readAllAndClose(t, post2)

	if st.Len() != 2 {
		t.Fatalf("Len before sweep = %d, want 2", st.Len())
	}

	fc.Advance(6 * time.Second)
	evicted := st.Sweep()
	if evicted != 2 {
		t.Fatalf("Sweep returned %d, want 2", evicted)
	}
	if st.Len() != 0 {
		t.Fatalf("Len after sweep = %d, want 0", st.Len())
	}
	if st.StoreBytes() != 0 {
		t.Fatalf("StoreBytes after sweep = %d, want 0", st.StoreBytes())
	}
}

// 32. TestGC_PreservesLive — mixed TTLs; Sweep evicts only expired.
func TestGC_PreservesLive(t *testing.T) {
	st, srv, fc := newTestEnv(t)

	shortPath := testSlotPath(t, fc.Now())
	svcHex := strings.Split(shortPath, "/")[1]
	longSlot := bytes.Repeat([]byte{0xDD}, 16)
	longPath := "/" + svcHex + "/" + hex.EncodeToString(longSlot)

	post1 := postWithToken(t, srv, shortPath+"?ttl=5", []byte("short"), testWriteTokenHex)
	_ = readAllAndClose(t, post1)
	post2 := postWithToken(t, srv, longPath+"?ttl=600", []byte("long-lived"), testWriteTokenHex)
	_ = readAllAndClose(t, post2)

	fc.Advance(6 * time.Second)
	evicted := st.Sweep()
	if evicted != 1 {
		t.Fatalf("Sweep returned %d, want 1", evicted)
	}
	if st.Len() != 1 {
		t.Fatalf("Len after sweep = %d, want 1", st.Len())
	}

	// Live slot still GETtable.
	get := doGet(t, srv, longPath)
	body := readAllAndClose(t, get)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET live slot status = %d, want 200", get.StatusCode)
	}
	if !bytes.Equal(body, []byte("long-lived")) {
		t.Fatalf("live-slot body mismatch")
	}
}

// 33. TestGC_StartStop — 10 ms ticker sweeps an expired slot in real
// time; Stop cleanly exits the goroutine.
func TestGC_StartStop(t *testing.T) {
	st, srv, fc := newTestEnv(t)

	gc := relay.NewGC(st, 10*time.Millisecond)
	gc.Start()
	defer gc.Stop()

	path := testSlotPath(t, fc.Now())
	post := postWithToken(t, srv, path+"?ttl=1", []byte("sweepme"), testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if st.Len() != 1 {
		t.Fatalf("Len after POST = %d, want 1", st.Len())
	}

	// Advance the FakeClock past the slot's expiresAt. Sweep uses
	// store.clock.Now(), so this makes the entry look expired to the
	// GC goroutine regardless of wall-clock elapsed.
	fc.Advance(2 * time.Second)

	// Wait long enough for at least one 10 ms tick to fire. Poll up
	// to 2 s so a heavily loaded CI runner does not flake.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st.Len() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Len() != 0 {
		t.Fatalf("GC did not sweep expired slot in time: Len = %d", st.Len())
	}
}

// 34. TestDelete_AfterReadsExhausted — AC-DEL-03: DELETE after the
// slot has been drained by Take → 404 (no oracle).
func TestDelete_AfterReadsExhausted(t *testing.T) {
	_, srv, fc := newTestEnv(t)
	path := testSlotPath(t, fc.Now())
	token := bytes.Repeat([]byte{0x5A}, 32)
	hash := sha256.Sum256(token)

	post := postWithTokenAndHash(t, srv, path, []byte("one-shot"),
		testWriteTokenHex, hex.EncodeToString(hash[:]))
	_ = readAllAndClose(t, post)

	get := doGet(t, srv, path)
	_ = readAllAndClose(t, get)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("drain GET status = %d, want 200", get.StatusCode)
	}

	del := doDelete(t, srv, path, hex.EncodeToString(token))
	_ = readAllAndClose(t, del)
	if del.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE after drain status = %d, want 404", del.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Tests 35-42: semaphore gate, store cap, ZeroizeAll,
// graceful shutdown.
// ---------------------------------------------------------------------------

// 35. TestSemaphore_503 — AC-OVERLOAD-01. With maxConcurrentGets=1,
// the first GET holds the semaphore (via GetHook blocking on holdCh)
// while a second GET on the same slot must fail fast with 503.
func TestSemaphore_503(t *testing.T) {
	holdCh := make(chan struct{})
	readyCh := make(chan struct{}, 1)
	hook := func() {
		readyCh <- struct{}{}
		<-holdCh
	}
	_, srv, fc := newTestEnvWithCap(t, 0, 1, hook)

	path := testSlotPath(t, fc.Now())
	post := postWithToken(t, srv, path, []byte("payload"), testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}

	type result struct {
		status int
		body   []byte
		err    error
	}
	firstDone := make(chan result, 1)
	go func() {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			firstDone <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		firstDone <- result{status: resp.StatusCode, body: body}
	}()

	// Wait for the first GET to acquire the semaphore and enter the hook.
	select {
	case <-readyCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("first GET never entered the hook")
	}

	// Second GET — semaphore is full, must 503 immediately.
	second := doGet(t, srv, path)
	secondBody := readAllAndClose(t, second)
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second GET status = %d, want 503", second.StatusCode)
	}
	if len(secondBody) != 0 {
		t.Fatalf("503 body must be empty, got %d bytes", len(secondBody))
	}

	// Release the first GET.
	close(holdCh)
	select {
	case r := <-firstDone:
		if r.err != nil {
			t.Fatalf("first GET: %v", r.err)
		}
		if r.status != http.StatusOK {
			t.Fatalf("first GET status = %d, want 200", r.status)
		}
		if !bytes.Equal(r.body, []byte("payload")) {
			t.Fatalf("first GET body mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("first GET never completed after hook release")
	}
}

// 36. TestSemaphore_ReleasesAfterGet — sequential GETs with gate=1
// both succeed because the defer releases the slot.
func TestSemaphore_ReleasesAfterGet(t *testing.T) {
	_, srv, fc := newTestEnvWithCap(t, 0, 1, nil)

	pathA := testSlotPath(t, fc.Now())
	postA := postWithToken(t, srv, pathA, []byte("A"), testWriteTokenHex)
	_ = readAllAndClose(t, postA)

	getA := doGet(t, srv, pathA)
	bodyA := readAllAndClose(t, getA)
	if getA.StatusCode != http.StatusOK || !bytes.Equal(bodyA, []byte("A")) {
		t.Fatalf("GET A: status=%d body=%q", getA.StatusCode, bodyA)
	}

	// Second POST under a different slot_id so Put does not 409.
	svcHex := strings.Split(pathA, "/")[1]
	slotB := bytes.Repeat([]byte{0xBB}, 16)
	pathB := "/" + svcHex + "/" + hex.EncodeToString(slotB)
	postB := postWithToken(t, srv, pathB, []byte("B"), testWriteTokenHex)
	_ = readAllAndClose(t, postB)

	getB := doGet(t, srv, pathB)
	bodyB := readAllAndClose(t, getB)
	if getB.StatusCode != http.StatusOK || !bytes.Equal(bodyB, []byte("B")) {
		t.Fatalf("GET B: status=%d body=%q", getB.StatusCode, bodyB)
	}
}

// 37. TestSemaphore_Unlimited — maxConcurrentGets=0 → no semaphore,
// POST + GET flow unaffected, no panic on the nil channel.
func TestSemaphore_Unlimited(t *testing.T) {
	_, srv, fc := newTestEnvWithCap(t, 0, 0, nil)
	path := testSlotPath(t, fc.Now())
	post := postWithToken(t, srv, path, []byte("unlimited"), testWriteTokenHex)
	_ = readAllAndClose(t, post)

	get := doGet(t, srv, path)
	body := readAllAndClose(t, get)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", get.StatusCode)
	}
	if !bytes.Equal(body, []byte("unlimited")) {
		t.Fatalf("GET body mismatch")
	}
}

// 38. TestStoreCap_503 — POST that would push total past the cap
// rejects with 503.
func TestStoreCap_503(t *testing.T) {
	_, srv, fc := newTestEnvWithCap(t, 100, 0, nil)
	basePath := testSlotPath(t, fc.Now())
	svcHex := strings.Split(basePath, "/")[1]

	post1 := postWithToken(t, srv, basePath, bytes.Repeat([]byte{0x01}, 60), testWriteTokenHex)
	_ = readAllAndClose(t, post1)
	if post1.StatusCode != http.StatusCreated {
		t.Fatalf("first POST status = %d, want 201", post1.StatusCode)
	}

	slotB := bytes.Repeat([]byte{0xBB}, 16)
	pathB := "/" + svcHex + "/" + hex.EncodeToString(slotB)
	post2 := postWithToken(t, srv, pathB, bytes.Repeat([]byte{0x02}, 60), testWriteTokenHex)
	body2 := readAllAndClose(t, post2)
	if post2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second POST status = %d, want 503", post2.StatusCode)
	}
	if len(body2) != 0 {
		t.Fatalf("503 body must be empty, got %d bytes", len(body2))
	}
}

// 39. TestStoreCap_ExactFit — cap=100, POST 100 → 201, StoreBytes=100.
func TestStoreCap_ExactFit(t *testing.T) {
	st, srv, fc := newTestEnvWithCap(t, 100, 0, nil)
	path := testSlotPath(t, fc.Now())
	post := postWithToken(t, srv, path, bytes.Repeat([]byte{0x03}, 100), testWriteTokenHex)
	_ = readAllAndClose(t, post)
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", post.StatusCode)
	}
	if st.StoreBytes() != 100 {
		t.Fatalf("StoreBytes = %d, want 100", st.StoreBytes())
	}
}

// 40. TestStoreCap_PostAfterEviction — expired-entry eviction inside
// Put reclaims bytes BEFORE the cap check, so a re-POST to the same
// slot_id after TTL expiry succeeds.
func TestStoreCap_PostAfterEviction(t *testing.T) {
	st, srv, fc := newTestEnvWithCap(t, 100, 0, nil)
	path := testSlotPath(t, fc.Now())

	post1 := postWithToken(t, srv, path+"?ttl=1",
		bytes.Repeat([]byte{0x04}, 100), testWriteTokenHex)
	_ = readAllAndClose(t, post1)
	if post1.StatusCode != http.StatusCreated {
		t.Fatalf("first POST status = %d, want 201", post1.StatusCode)
	}

	fc.Advance(2 * time.Second)

	post2 := postWithToken(t, srv, path,
		bytes.Repeat([]byte{0x05}, 100), testWriteTokenHex)
	_ = readAllAndClose(t, post2)
	if post2.StatusCode != http.StatusCreated {
		t.Fatalf("second POST status = %d, want 201 (eviction should free space)", post2.StatusCode)
	}
	if st.StoreBytes() != 100 {
		t.Fatalf("StoreBytes = %d, want 100 after re-POST", st.StoreBytes())
	}
}

// 41. TestZeroizeAll — three POSTs, ZeroizeAll returns 3, counters
// reset, subsequent GETs 404.
func TestZeroizeAll(t *testing.T) {
	st, srv, fc := newTestEnvWithCap(t, 0, 0, nil)
	basePath := testSlotPath(t, fc.Now())
	svcHex := strings.Split(basePath, "/")[1]

	paths := make([]string, 3)
	for i, b := range []byte{0xA1, 0xA2, 0xA3} {
		slotBytes := bytes.Repeat([]byte{b}, 16)
		paths[i] = "/" + svcHex + "/" + hex.EncodeToString(slotBytes)
		p := postWithToken(t, srv, paths[i], []byte{b}, testWriteTokenHex)
		_ = readAllAndClose(t, p)
		if p.StatusCode != http.StatusCreated {
			t.Fatalf("POST %d status = %d, want 201", i, p.StatusCode)
		}
	}
	if st.Len() != 3 {
		t.Fatalf("Len before zeroize = %d, want 3", st.Len())
	}

	evicted := st.ZeroizeAll()
	if evicted != 3 {
		t.Fatalf("ZeroizeAll returned %d, want 3", evicted)
	}
	if st.Len() != 0 {
		t.Fatalf("Len after zeroize = %d, want 0", st.Len())
	}
	if st.StoreBytes() != 0 {
		t.Fatalf("StoreBytes after zeroize = %d, want 0", st.StoreBytes())
	}
	for _, p := range paths {
		g := doGet(t, srv, p)
		_ = readAllAndClose(t, g)
		if g.StatusCode != http.StatusNotFound {
			t.Fatalf("GET after zeroize status = %d, want 404", g.StatusCode)
		}
	}
}

// 42. TestGracefulShutdown_SignalPath — assemble the lifecycle
// manually (not via run()) so the test has direct access to the
// Store and can assert ZeroizeAll wiped it. Mirrors the
// shutdown → drain → zeroize path in cmd/deaddrop-relay/main.go.
func TestGracefulShutdown_SignalPath(t *testing.T) {
	fc := clock.NewFakeClock(testStartTime())
	st := relay.NewStore(fc, 0)
	handler := relay.NewHandler(relay.Config{
		Store:        st,
		DeploySecret: testDeploySecret(),
		WriteToken:   []byte(testWriteTokenStr),
		MaxBlobBytes: testMaxBlobBytes,
		Clock:        fc,
	})
	gc := relay.NewGC(st, time.Second)
	gc.Start()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ln) }()

	// POST a slot over the real listener.
	url := "http://" + ln.Addr().String() + testSlotPath(t, fc.Now())
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte("to-zeroize")))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-DeadDrop-Write", testWriteTokenHex)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", resp.StatusCode)
	}
	if st.Len() != 1 {
		t.Fatalf("Len after POST = %d, want 1", st.Len())
	}

	// Shutdown path: Shutdown, then Stop GC and zeroize.
	shutdownDone := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		gc.Stop()
		st.ZeroizeAll()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("shutdown did not complete within 5s")
	}

	if st.Len() != 0 {
		t.Fatalf("Len after shutdown = %d, want 0 (ZeroizeAll did not run on the POSTed slot)", st.Len())
	}
	if st.StoreBytes() != 0 {
		t.Fatalf("StoreBytes after shutdown = %d, want 0", st.StoreBytes())
	}
	// srv.Serve returns ErrServerClosed as soon as Shutdown closes the listener.
	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("srv.Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("srv.Serve did not return after Shutdown")
	}
}
