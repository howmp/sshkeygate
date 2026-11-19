#!/bin/sh
# Adds the macOS 11 compatibility shim to an app bundle.
#
# Go 1.27 links crypto/x509 for macOS 13 and imports
# SecTrustCopyCertificateChain, which macOS 12 introduced, so dyld refuses to
# start the app on macOS 11. The shim implements that symbol with the API it
# replaced, and the app's executable becomes a script that injects it.
#
#	macos11-compat.sh <app bundle> [source dir]
#
# The source dir holds sectrust_compat.c, and defaults to this script's.
set -eu

app=${1:?usage: macos11-compat.sh <app bundle> [source dir]}
here=$(cd "$(dirname "$0")" && pwd)
src=${2:-$here}

if [ ! -d "$app" ]; then
	echo "no app bundle at $app" >&2
	exit 1
fi

bin="$app/Contents/MacOS/sshkeygate"
frameworks="$app/Contents/Frameworks"
mkdir -p "$frameworks"

# The shim is built for both architectures even on a machine of one of them,
# so a single download runs on Intel and Apple Silicon alike.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Each slice is compiled and linked on its own, then lipo joins them: clang
# makes a library of the host's architecture only, so linking once would ship
# one slice and fail on the other kind of Mac.
libs=""
for arch in arm64 x86_64; do
	# -mmacosx-version-min keeps the shim's own deployment target at 11, where
	# its deprecated APIs are still the right ones.
	clang -arch "$arch" -mmacosx-version-min=11.0 -c -O2 -DSECTRUST_COMPAT \
		-o "$work/compat_$arch.o" "$src/sectrust_compat.c"
	clang -arch "$arch" -dynamiclib -mmacosx-version-min=11.0 \
		-Wl,-exported_symbol,_SecTrustCopyCertificateChain \
		-framework Security -framework CoreFoundation \
		-o "$work/compat_$arch.dylib" "$work/compat_$arch.o"
	libs="$libs $work/compat_$arch.dylib"
done
# shellcheck disable=SC2086
lipo -create $libs -output "$frameworks/libsectrust_compat.dylib"

# A library with one slice would fail to load on the other kind of Mac, and
# the failure would only show up there.
want="arm64 x86_64"
got=$(lipo -archs "$frameworks/libsectrust_compat.dylib" 2>/dev/null | tr ' ' '\n' | sort | tr '\n' ' ')
for arch in $want; do
	case " $got " in
	*" $arch "*) ;;
	*)
		echo "the shim lacks $arch: $got" >&2
		exit 1
		;;
	esac
done

# The shim must export the symbol and not import it.
if [ -z "$(nm -g "$frameworks/libsectrust_compat.dylib" | grep _SecTrustCopyCertificateChain || true)" ]; then
	echo "the shim does not export SecTrustCopyCertificateChain" >&2
	exit 1
fi
if [ -n "$(nm -u "$frameworks/libsectrust_compat.dylib" | grep _SecTrustCopyCertificateChain || true)" ]; then
	echo "the shim imports SecTrustCopyCertificateChain" >&2
	exit 1
fi

# The executable becomes a script that injects the shim before starting the
# real binary, which keeps its name for the signature and the Dock.
mv "$bin" "$bin.bin"
cat >"$bin" <<'LAUNCHER'
#!/bin/sh
# Starts the app with the macOS 11 compatibility shim, for the symbol Go 1.27
# imports and macOS 12 added. Everything else passes through untouched.
dir=$(cd "$(dirname "$0")" && pwd)
shim="$dir/../Frameworks/libsectrust_compat.dylib"
if [ -f "$shim" ]; then
	DYLD_INSERT_LIBRARIES="$shim"
	DYLD_FORCE_FLAT_NAMESPACE=1
	export DYLD_INSERT_LIBRARIES DYLD_FORCE_FLAT_NAMESPACE
fi
exec "$dir/sshkeygate.bin" "$@"
LAUNCHER
chmod 755 "$bin" "$bin.bin"

echo "added the macOS 11 shim to $app"
