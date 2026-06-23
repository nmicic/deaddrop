// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && passcache_keychain

// This file holds cgo helpers used only by the keychain integration
// tests. cgo is not allowed inside `_test.go` files, so the helpers
// live here behind the `passcache_keychain` build tag — which means
// production builds never see this file.

package passcache

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static OSStatus ddTestQuerySync(CFStringRef service, CFStringRef account,
        int *outFound, int *outSyncPresent, int *outSyncValue) {
    *outFound = 0; *outSyncPresent = 0; *outSyncValue = 0;
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) return -1;
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrService, service);
    CFDictionarySetValue(q, kSecAttrAccount, account);
    CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching(q, &result);
    CFRelease(q);
    if (s == errSecItemNotFound) {
        return errSecItemNotFound;
    }
    if (s != errSecSuccess) {
        return s;
    }
    *outFound = 1;
    CFDictionaryRef attrs = (CFDictionaryRef)result;
    CFTypeRef sync = NULL;
    if (CFDictionaryGetValueIfPresent(attrs, kSecAttrSynchronizable, (const void **)&sync) && sync != NULL) {
        *outSyncPresent = 1;
        if (CFEqual(sync, kCFBooleanTrue)) {
            *outSyncValue = 1;
        } else {
            *outSyncValue = 0;
        }
    }
    CFRelease(result);
    return errSecSuccess;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// testQuerySynchronizable looks up the {service=deaddrop, account=id}
// generic-password item with kSecReturnAttributes=true and reports
// whether the kSecAttrSynchronizable attribute is present and, if so,
// whether it is true. Used only by NoiCloudSync regression tests.
func testQuerySynchronizable(id string) (found, syncPresent, syncValue bool, err error) {
	svc := []byte(serviceName)
	acct := []byte(id)
	cfSvc := C.CFStringCreateWithBytes(C.kCFAllocatorDefault,
		(*C.UInt8)(unsafe.Pointer(&svc[0])), C.CFIndex(len(svc)),
		C.kCFStringEncodingUTF8, C.Boolean(0))
	if cfSvc == 0 {
		return false, false, false, fmt.Errorf("CFStringCreateWithBytes(service) returned NULL")
	}
	defer C.CFRelease(C.CFTypeRef(cfSvc))
	cfAcct := C.CFStringCreateWithBytes(C.kCFAllocatorDefault,
		(*C.UInt8)(unsafe.Pointer(&acct[0])), C.CFIndex(len(acct)),
		C.kCFStringEncodingUTF8, C.Boolean(0))
	if cfAcct == 0 {
		return false, false, false, fmt.Errorf("CFStringCreateWithBytes(account) returned NULL")
	}
	defer C.CFRelease(C.CFTypeRef(cfAcct))

	var cFound, cSyncPresent, cSyncValue C.int
	status := C.ddTestQuerySync(cfSvc, cfAcct, &cFound, &cSyncPresent, &cSyncValue)
	if status != 0 && status != errSecItemNotFound {
		return false, false, false, fmt.Errorf("ddTestQuerySync: OSStatus %d", int(status))
	}
	return cFound != 0, cSyncPresent != 0, cSyncValue != 0, nil
}
