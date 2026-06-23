// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package passcache

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// All the cgo dance lives in C-land. The Go side calls these helpers
// and never touches kSecXxx constants or kCFBooleanTrue directly —
// avoids `go vet` warnings about unsafe.Pointer-casting void*-shaped
// CF constants (every CFTypeRef in cgo is *C.struct___CFType).

// ddCFString creates a CFStringRef from a UTF-8 byte buffer. Returns
// NULL on bad input; on success the caller must CFRelease.
static CFStringRef ddCFString(const char *bytes, int len) {
    if (bytes == NULL || len < 0) return NULL;
    return CFStringCreateWithBytes(kCFAllocatorDefault,
        (const UInt8 *)bytes, (CFIndex)len,
        kCFStringEncodingUTF8, false);
}

// ddCFData copies the provided bytes into a fresh CFDataRef. Caller
// must CFRelease.
static CFDataRef ddCFData(const void *bytes, int len) {
    if (bytes == NULL || len < 0) return NULL;
    return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)bytes, (CFIndex)len);
}

// ddBuildBaseQuery constructs the {class=GenericPassword, service,
// account} dictionary shared by Get/Put/Update/Forget. Returns a
// mutable dictionary the caller must CFRelease.
static CFMutableDictionaryRef ddBuildBaseQuery(CFStringRef service, CFStringRef account) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) return NULL;
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    if (service) CFDictionarySetValue(q, kSecAttrService, service);
    if (account) CFDictionarySetValue(q, kSecAttrAccount, account);
    return q;
}

// ddSetReturnDataAndLimitOne configures a query to ask for the value
// data of exactly one matching item.
static void ddSetReturnDataAndLimitOne(CFMutableDictionaryRef q) {
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
}

// ddSetValueAndAccessibility installs the value-data + accessibility
// attributes used by SecItemAdd.
static void ddSetValueAndAccessibility(CFMutableDictionaryRef attrs, CFDataRef value) {
    CFDictionarySetValue(attrs, kSecValueData, value);
    CFDictionarySetValue(attrs, kSecAttrAccessible,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
}

// ddBuildUpdateAttrs constructs the update-attributes dictionary
// containing only the new value-data field.
static CFMutableDictionaryRef ddBuildUpdateAttrs(CFDataRef value) {
    CFMutableDictionaryRef u = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (u == NULL) return NULL;
    CFDictionarySetValue(u, kSecValueData, value);
    return u;
}

// ddSecItemCopyData wraps SecItemCopyMatching so we can pass the
// CFDataRef back via an out-pointer typed as CFDataRef (cgo struggles
// with CFTypeRef* casts otherwise). Returns OSStatus; on success
// *outData is non-NULL and the caller must CFRelease it.
static OSStatus ddSecItemCopyData(CFDictionaryRef query, CFDataRef *outData) {
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching(query, &result);
    if (s == errSecSuccess) {
        *outData = (CFDataRef)result;
    } else {
        *outData = NULL;
    }
    return s;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

const (
	serviceName = "deaddrop"

	// Apple OSStatus values for keychain item lookup. Keep these as Go
	// constants so we don't have to round-trip through cgo for every
	// equality check.
	errSecSuccess       = 0
	errSecItemNotFound  = -25300
	errSecDuplicateItem = -25299
)

type keychainCache struct{}

// New constructs the macOS Keychain backend. The constructor itself
// has no failure mode (no syscalls needed at construction); errors
// surface from Get/Put/Forget at use time.
func New() (Cache, error) {
	return &keychainCache{}, nil
}

// cfString creates a CFStringRef from a Go string. Caller must
// CFRelease the returned ref.
func cfString(s string) C.CFStringRef {
	if len(s) == 0 {
		return C.ddCFString(nil, 0)
	}
	b := []byte(s)
	return C.ddCFString((*C.char)(unsafe.Pointer(&b[0])), C.int(len(b)))
}

// cfData creates a CFDataRef from a C-allocated byte buffer. CFData
// copies on construction so the underlying buffer does not need to
// outlive the call. Caller must CFRelease the returned ref.
func cfData(buf unsafe.Pointer, length C.int) C.CFDataRef {
	return C.ddCFData(buf, length)
}

func (c *keychainCache) Get(id string) ([]byte, error) {
	service := cfString(serviceName)
	defer C.CFRelease(C.CFTypeRef(service))
	account := cfString(id)
	defer C.CFRelease(C.CFTypeRef(account))

	query := C.ddBuildBaseQuery(service, account)
	if query == 0 {
		return nil, errors.New("passcache: CFDictionaryCreateMutable failed")
	}
	defer C.CFRelease(C.CFTypeRef(query))
	C.ddSetReturnDataAndLimitOne(query)

	var data C.CFDataRef
	status := C.ddSecItemCopyData(C.CFDictionaryRef(query), &data)
	if status == errSecItemNotFound {
		return nil, ErrMiss
	}
	if status != errSecSuccess {
		// Treat any non-success non-NotFound result as a miss for the
		// caller (e.g., locked keychain). Documented in the spec's risk
		// surface — Get failures degrade to ErrMiss; the splice prompts
		// and the next Put will surface the underlying error via
		// strictCache.
		return nil, ErrMiss
	}
	if data == 0 {
		return nil, ErrMiss
	}
	defer C.CFRelease(C.CFTypeRef(data))

	length := int(C.CFDataGetLength(data))
	if length == 0 {
		return []byte{}, nil
	}
	ptr := C.CFDataGetBytePtr(data)
	out := make([]byte, length)
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(ptr), C.size_t(length))
	return out, nil
}

func (c *keychainCache) Put(id string, pass []byte, ttl time.Duration) error {
	// ttl is intentionally ignored — design decision 5. The CLI surface
	// emits the TTL-asymmetry warning when the operator passes
	// --passcache-ttl explicitly.
	_ = ttl

	if len(pass) == 0 {
		// Guard against a zero-length passphrase being stored. Keychain
		// would accept it; semantically meaningless for our use case.
		return errors.New("passcache: refusing to store empty passphrase")
	}
	// Copy passphrase into a C-allocated buffer so we can zero it after
	// the CFData copy; the Go []byte caller is responsible for its own
	// hygiene. CFDataCreate copies internally, so the C buffer can be
	// freed/zeroed once the CFData is built.
	cBuf := C.CBytes(pass)
	cLen := C.int(len(pass))
	defer func() {
		// Zero the C-side scratch before freeing — same hygiene as the
		// Go-side zeroize helper.
		C.memset(cBuf, 0, C.size_t(cLen))
		C.free(cBuf)
	}()

	// Try Add → on duplicate, fall back to Update. On Update-not-found
	// (concurrent Forget), retry the Add cycle exactly once.
	for attempt := 0; attempt < 2; attempt++ {
		status := keychainAdd(id, cBuf, cLen)
		if status == errSecSuccess {
			return nil
		}
		if status != errSecDuplicateItem {
			return fmt.Errorf("passcache: SecItemAdd failed: OSStatus %d", int(status))
		}
		// Duplicate: try Update.
		status = keychainUpdate(id, cBuf, cLen)
		if status == errSecSuccess {
			return nil
		}
		if status == errSecItemNotFound && attempt == 0 {
			// Concurrent Forget between our Add and Update — retry Add.
			continue
		}
		return fmt.Errorf("passcache: SecItemUpdate failed: OSStatus %d", int(status))
	}
	// Two ping-pongs: surface the duplicate verbatim per design decision 7.
	return fmt.Errorf("passcache: SecItemAdd failed: OSStatus %d (duplicate after retry)", errSecDuplicateItem)
}

// keychainAdd builds the full attribute dictionary and calls SecItemAdd.
// cBuf points to a C-allocated copy of the passphrase; CFDataCreate
// copies it internally, so the buffer lifetime is independent of the
// keychain item.
func keychainAdd(id string, cBuf unsafe.Pointer, cLen C.int) C.OSStatus {
	service := cfString(serviceName)
	defer C.CFRelease(C.CFTypeRef(service))
	account := cfString(id)
	defer C.CFRelease(C.CFTypeRef(account))

	value := cfData(cBuf, cLen)
	if value == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(value))

	attrs := C.ddBuildBaseQuery(service, account)
	if attrs == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(attrs))
	C.ddSetValueAndAccessibility(attrs, value)

	return C.SecItemAdd(C.CFDictionaryRef(attrs), nil)
}

// keychainUpdate runs SecItemUpdate against the {class, service,
// account} query, updating only the value-data field.
func keychainUpdate(id string, cBuf unsafe.Pointer, cLen C.int) C.OSStatus {
	service := cfString(serviceName)
	defer C.CFRelease(C.CFTypeRef(service))
	account := cfString(id)
	defer C.CFRelease(C.CFTypeRef(account))

	query := C.ddBuildBaseQuery(service, account)
	if query == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(query))

	value := cfData(cBuf, cLen)
	if value == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(value))

	updateAttrs := C.ddBuildUpdateAttrs(value)
	if updateAttrs == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(updateAttrs))

	return C.SecItemUpdate(C.CFDictionaryRef(query), C.CFDictionaryRef(updateAttrs))
}

func (c *keychainCache) Forget(id string) error {
	service := cfString(serviceName)
	defer C.CFRelease(C.CFTypeRef(service))
	account := cfString(id)
	defer C.CFRelease(C.CFTypeRef(account))

	query := C.ddBuildBaseQuery(service, account)
	if query == 0 {
		return errors.New("passcache: CFDictionaryCreateMutable failed")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(C.CFDictionaryRef(query))
	if status == errSecSuccess || status == errSecItemNotFound {
		// Idempotent — already absent is success.
		return nil
	}
	return fmt.Errorf("passcache: SecItemDelete failed: OSStatus %d", int(status))
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
