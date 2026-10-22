#!/usr/bin/env bash
# Builds build/mac-debug/ProxyGo-debug.app, a macOS debug build that runs
# beside a release ProxyGo: it keeps MyGo's development features (such as the
# web inspector), has its own name, bundle identifier and data directory, and
# wears the debug icon (the ProxyGo mark in pink on black). Its settings start
# from the defaults, so give it another proxy port than 9090 to run both at
# once.
#
#   scripts/build-mac-debug.sh          # build build/mac-debug/ProxyGo-debug.app
#   scripts/build-mac-debug.sh --open   # build, then launch it
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
	echo "build-mac-debug.sh builds a macOS app; run it on macOS." >&2
	exit 1
fi
for tool in go xcrun python3 plutil codesign; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "build-mac-debug.sh needs $tool." >&2
		exit 1
	fi
done

open_app=false
for arg in "$@"; do
	case "$arg" in
	--open) open_app=true ;;
	-h | --help)
		sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "Unknown option: $arg" >&2
		exit 1
		;;
	esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

name="ProxyGo-debug"
identifier="com.example.proxygo.debug"
# ProxyGo keeps its data in ~/Library/Application Support/ProxyGo unless
# PROXYGO_DATA_DIR names another folder, which macOS sets from the bundle's
# LSEnvironment when it launches the app.
data_dir="$HOME/Library/Application Support/$name"
case "$(uname -m)" in
arm64) arch=arm64 ;;
x86_64) arch=amd64 ;;
*)
	echo "Unsupported architecture: $(uname -m)" >&2
	exit 1
	;;
esac
# Beside build/mac-release, and out of mygo build's own build/darwin-*.
out="build/mac-debug"
built="$out/darwin-$arch/ProxyGo.app"
app="$out/$name.app"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> Building debug app for darwin/$arch"
go tool mygo build -debug -skip-dmg -platform "darwin/$arch" -o "$out"
if [[ ! -d "$built" ]]; then
	echo "Expected $built after the build." >&2
	exit 1
fi
plist="$built/Contents/Info.plist"

echo "==> Drawing the debug icon"
# The release icon's Icon Composer layers, recolored as the Neon app icon.
python3 -I scripts/lib/recolor-icon.py assets/icon/AppIcon.icon "$work/AppIcon.icon" neon
# actool renders the asset catalog for macOS 26 and later, and the .icns of
# older systems, as mygo build does with the release icon.
mkdir "$work/icon"
if xcrun actool "$work/AppIcon.icon" --compile "$work/icon" --output-format human-readable-text \
	--platform macosx --target-device mac \
	--minimum-deployment-target "$(plutil -extract LSMinimumSystemVersion raw "$plist")" \
	--app-icon AppIcon --output-partial-info-plist "$work/icon/partial.plist" >"$work/actool.log" 2>&1 &&
	[[ -f "$work/icon/Assets.car" && -f "$work/icon/AppIcon.icns" ]]; then
	cp "$work/icon/Assets.car" "$work/icon/AppIcon.icns" "$built/Contents/Resources/"
	plutil -replace CFBundleIconFile -string AppIcon.icns "$plist"
	plutil -replace CFBundleIconName -string AppIcon "$plist"
else
	cat "$work/actool.log" >&2
	echo "warning: actool could not compile the debug icon (it needs Xcode 26 or later); keeping the release icon" >&2
fi

echo "==> Packaging $name.app"
plutil -replace CFBundleName -string "$name" "$plist"
plutil -replace CFBundleDisplayName -string "$name" "$plist"
plutil -replace CFBundleIdentifier -string "$identifier" "$plist"
plutil -replace LSEnvironment -dictionary "$plist"
plutil -replace LSEnvironment.PROXYGO_DATA_DIR -string "$data_dir" "$plist"
rm -rf "$app"
mv "$built" "$app"
# MyGo builds into a per-platform folder, empty once the app moves out.
rmdir "$(dirname "$built")" 2>/dev/null || true

echo "==> Signing (ad hoc)"
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"

echo "Built $root/$app"
if $open_app; then
	open "$app"
fi
