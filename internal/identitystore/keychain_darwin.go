// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package identitystore

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Mirrors the cgo dance in passcache/keychain_darwin.go. All
// kSecXxx / kCFBooleanTrue references stay C-side so cgo's
// CFTypeRef ↔ unsafe.Pointer mismatch never surfaces in Go.

static CFStringRef ddidCFString(const char *bytes, int len) {
    if (bytes == NULL || len < 0) return NULL;
    return CFStringCreateWithBytes(kCFAllocatorDefault,
        (const UInt8 *)bytes, (CFIndex)len,
        kCFStringEncodingUTF8, false);
}

static CFDataRef ddidCFData(const void *bytes, int len) {
    if (bytes == NULL || len < 0) return NULL;
    return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)bytes, (CFIndex)len);
}

static CFMutableDictionaryRef ddidBuildBaseQuery(CFStringRef service, CFStringRef account) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) return NULL;
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    if (service) CFDictionarySetValue(q, kSecAttrService, service);
    if (account) CFDictionarySetValue(q, kSecAttrAccount, account);
    return q;
}

static void ddidSetReturnDataAndLimitOne(CFMutableDictionaryRef q) {
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
}

static void ddidSetValueAndAccessibility(CFMutableDictionaryRef attrs, CFDataRef value) {
    CFDictionarySetValue(attrs, kSecValueData, value);
    CFDictionarySetValue(attrs, kSecAttrAccessible,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
}

static CFMutableDictionaryRef ddidBuildUpdateAttrs(CFDataRef value) {
    CFMutableDictionaryRef u = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (u == NULL) return NULL;
    CFDictionarySetValue(u, kSecValueData, value);
    return u;
}

static OSStatus ddidSecItemCopyData(CFDictionaryRef query, CFDataRef *outData) {
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
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

const (
	// idServiceName is intentionally distinct from passcache's
	// "deaddrop". An operator running
	//   security delete-generic-password -s deaddrop
	// to clear the passphrase cache must NOT also wipe identity
	// entries, which would silently break their pairs (D-62).
	idServiceName = "deaddrop-identity"

	idErrSecSuccess       = 0
	idErrSecItemNotFound  = -25300
	idErrSecDuplicateItem = -25299
)

type keychainStore struct{}

// newKeychainStore is the test seam mirror of passcache's newCache.
// Production code never reassigns it; tests can swap in a fake.
var newKeychainStore = newKeychainStoreReal

func newKeychainStoreReal() (Store, error) { return &keychainStore{}, nil }

// New constructs the macOS Keychain identitystore backend. As with
// the passcache equivalent, the constructor itself has no failure
// mode (no syscalls at construction time); errors surface at use.
func New() (Store, error) { return newKeychainStore() }

// account derives the keychain account string for a pair. Format is
// distinct from the passcache "deaddrop:<hex8>" prefix so the two
// services never collide in operator-facing tooling.
func account(pairID [8]byte) string {
	return "deaddrop:pair:" + hex.EncodeToString(pairID[:])
}

func cfString(s string) C.CFStringRef {
	if len(s) == 0 {
		return C.ddidCFString(nil, 0)
	}
	b := []byte(s)
	return C.ddidCFString((*C.char)(unsafe.Pointer(&b[0])), C.int(len(b)))
}

func cfData(buf unsafe.Pointer, length C.int) C.CFDataRef {
	return C.ddidCFData(buf, length)
}

func (c *keychainStore) Get(pairID [8]byte) (*Entry, error) {
	service := cfString(idServiceName)
	defer C.CFRelease(C.CFTypeRef(service))
	acct := cfString(account(pairID))
	defer C.CFRelease(C.CFTypeRef(acct))

	query := C.ddidBuildBaseQuery(service, acct)
	if query == 0 {
		return nil, errors.New("identitystore: CFDictionaryCreateMutable failed")
	}
	defer C.CFRelease(C.CFTypeRef(query))
	C.ddidSetReturnDataAndLimitOne(query)

	var data C.CFDataRef
	status := C.ddidSecItemCopyData(C.CFDictionaryRef(query), &data)
	if status == idErrSecItemNotFound {
		return nil, ErrMiss
	}
	if status != idErrSecSuccess {
		// Per D-62, malformed / locked-keychain reads degrade to
		// ErrMiss — operator-friendly path is "rebootstrap" rather
		// than a cryptic OSStatus number.
		return nil, ErrMiss
	}
	if data == 0 {
		return nil, ErrMiss
	}
	defer C.CFRelease(C.CFTypeRef(data))

	length := int(C.CFDataGetLength(data))
	if length != EntrySize {
		// Shape rejection per D-62 / D-64. Treat as miss.
		return nil, ErrMiss
	}
	ptr := C.CFDataGetBytePtr(data)
	blob := make([]byte, length)
	C.memcpy(unsafe.Pointer(&blob[0]), unsafe.Pointer(ptr), C.size_t(length))
	defer zeroize(blob)

	e, err := UnmarshalEntry(blob)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (c *keychainStore) Put(pairID [8]byte, e *Entry) error {
	if e == nil {
		return errors.New("identitystore: refusing to store nil entry")
	}
	if e.Role != RoleInitiator && e.Role != RoleResponder {
		return errors.New("identitystore: invalid role byte")
	}
	blob := MarshalEntry(e)
	defer zeroize(blob)

	cBuf := C.CBytes(blob)
	cLen := C.int(len(blob))
	defer func() {
		C.memset(cBuf, 0, C.size_t(cLen))
		C.free(cBuf)
	}()

	for attempt := 0; attempt < 2; attempt++ {
		status := keychainAdd(pairID, cBuf, cLen)
		if status == idErrSecSuccess {
			return nil
		}
		if status != idErrSecDuplicateItem {
			return fmt.Errorf("identitystore: SecItemAdd failed: OSStatus %d", int(status))
		}
		status = keychainUpdate(pairID, cBuf, cLen)
		if status == idErrSecSuccess {
			return nil
		}
		if status == idErrSecItemNotFound && attempt == 0 {
			// Concurrent Forget between Add and Update — retry Add
			// exactly once (mirrors passcache D-7).
			continue
		}
		return fmt.Errorf("identitystore: SecItemUpdate failed: OSStatus %d", int(status))
	}
	return fmt.Errorf("identitystore: SecItemAdd failed: OSStatus %d (duplicate after retry)", idErrSecDuplicateItem)
}

func keychainAdd(pairID [8]byte, cBuf unsafe.Pointer, cLen C.int) C.OSStatus {
	service := cfString(idServiceName)
	defer C.CFRelease(C.CFTypeRef(service))
	acct := cfString(account(pairID))
	defer C.CFRelease(C.CFTypeRef(acct))

	value := cfData(cBuf, cLen)
	if value == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(value))

	attrs := C.ddidBuildBaseQuery(service, acct)
	if attrs == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(attrs))
	C.ddidSetValueAndAccessibility(attrs, value)

	return C.SecItemAdd(C.CFDictionaryRef(attrs), nil)
}

func keychainUpdate(pairID [8]byte, cBuf unsafe.Pointer, cLen C.int) C.OSStatus {
	service := cfString(idServiceName)
	defer C.CFRelease(C.CFTypeRef(service))
	acct := cfString(account(pairID))
	defer C.CFRelease(C.CFTypeRef(acct))

	query := C.ddidBuildBaseQuery(service, acct)
	if query == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(query))

	value := cfData(cBuf, cLen)
	if value == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(value))

	updateAttrs := C.ddidBuildUpdateAttrs(value)
	if updateAttrs == 0 {
		return -1
	}
	defer C.CFRelease(C.CFTypeRef(updateAttrs))

	return C.SecItemUpdate(C.CFDictionaryRef(query), C.CFDictionaryRef(updateAttrs))
}

func (c *keychainStore) Forget(pairID [8]byte) error {
	service := cfString(idServiceName)
	defer C.CFRelease(C.CFTypeRef(service))
	acct := cfString(account(pairID))
	defer C.CFRelease(C.CFTypeRef(acct))

	query := C.ddidBuildBaseQuery(service, acct)
	if query == 0 {
		return errors.New("identitystore: CFDictionaryCreateMutable failed")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(C.CFDictionaryRef(query))
	if status == idErrSecSuccess || status == idErrSecItemNotFound {
		return nil
	}
	return fmt.Errorf("identitystore: SecItemDelete failed: OSStatus %d", int(status))
}
