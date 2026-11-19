/*
 * Compatibility shim for macOS 11: the Go 1.27 runtime and standard library
 * reference SecTrustCopyCertificateChain, which macOS 12 added. dyld refuses
 * to start a binary that imports a symbol the system lacks, so this defines
 * the symbol for the older system, implemented with the deprecated API that
 * it replaced.
 *
 * Built into a .syso and linked into the Go binary, which keeps the build
 * pure Go: no cgo, so any machine can cross-compile it.
 *
 * Based on github.com/ink-splatters/darwin-sectrust-compat (MIT).
 */
#include <TargetConditionals.h>

#if TARGET_OS_OSX

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

enum { COMPAT_MAX_CHAIN_LENGTH = 10 };

CFArrayRef SecTrustCopyCertificateChain(SecTrustRef trust) {
	if (trust == NULL) {
		return NULL;
	}

	/* Evaluate first, as the original does, and proceed whatever the
	 * result: the trust's certificate chain is returned either way. */
	CFErrorRef error = NULL;
	(void)SecTrustEvaluateWithError(trust, &error);
	if (error != NULL) {
		CFRelease(error);
	}

	CFIndex count = SecTrustGetCertificateCount(trust);
	if (count <= 0 || count > COMPAT_MAX_CHAIN_LENGTH) {
		return NULL;
	}

	const void *certs[COMPAT_MAX_CHAIN_LENGTH];
	CFIndex actual = 0;
	for (CFIndex i = 0; i < count; i++) {
		SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, i);
		if (cert != NULL) {
			certs[actual++] = cert;
		}
	}

	return CFArrayCreate(kCFAllocatorDefault, certs, actual, &kCFTypeArrayCallBacks);
}

#pragma clang diagnostic pop

#endif /* TARGET_OS_OSX */
