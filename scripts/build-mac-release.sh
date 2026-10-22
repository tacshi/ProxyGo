#!/usr/bin/env bash
# Builds ProxyGo's macOS release disk images, signed with a Developer ID and
# notarized: one for Apple silicon, one for Intel and a universal one.
#
#   scripts/build-mac-release.sh                  # the version in mygo.json
#   scripts/build-mac-release.sh 0.2.0            # another version
#   scripts/build-mac-release.sh --arch arm64     # only some: arm64, x64, universal
#   scripts/build-mac-release.sh --skip-notarize  # signed, not notarized (faster)
#   scripts/build-mac-release.sh -o out           # another output directory
#   scripts/build-mac-release.sh --upload         # and upload to a draft GitHub release
#   scripts/build-mac-release.sh --changelog f.md # notes from f.md, not CHANGELOG.md
#
# The disk images go to build/mac-release as
# ProxyGo-<version>-{arm64,x64,universal}.dmg, beside the signed update
# archives, deltas and manifests that installed copies update from. --upload
# puts them all in the draft release v<version> of tacshi/ProxyGo, with gh;
# installed copies see the update once the draft is published.
#
# Signs updates with MYGO_UPDATER_PRIVATE_KEY, else the key in the file
# PROXYGO_UPDATE_KEY, by default
#   ~/Library/Application Support/mygo/update-keys/ProxyGo/mygo-update.key
# made with
#   go tool mygo keygen -o ~/Library/Application\ Support/mygo/update-keys/ProxyGo
# Its public half is updates.publicKey in mygo.json.
#
# Signs with DEVELOPER_ID_APPLICATION, or the keychain's one Developer ID
# Application identity when it is not set, and notarizes with a notarytool
# keychain profile: PROXYGO_NOTARY_PROFILE, "ProxyGo" by default, made with
#   xcrun notarytool store-credentials ProxyGo --apple-id <id> --team-id <team>
# scripts/publish.sh runs this with --changelog, -o and --upload.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/release.sh"
cd "$ROOT_DIR"

VERSION=""
ARCHES=()
NOTARIZE=true
UPLOAD=false
CHANGELOG=""
OUT_DIR="$ROOT_DIR/build/mac-release"
while (($#)); do
	case "$1" in
	--arch)
		[[ $# -ge 2 ]] || die "--arch needs arm64, x64 or universal"
		ARCHES+=("$2")
		shift
		;;
	--skip-notarize) NOTARIZE=false ;;
	--upload) UPLOAD=true ;;
	--changelog)
		[[ $# -ge 2 ]] || die "--changelog needs a file"
		CHANGELOG="$2"
		shift
		;;
	-o)
		[[ $# -ge 2 ]] || die "-o needs a directory"
		OUT_DIR="$2"
		shift
		;;
	-h | --help)
		sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	-*) die "unknown option: $1" ;;
	*)
		[[ -z "$VERSION" ]] || die "one version, please: $VERSION or $1"
		VERSION="${1#v}"
		;;
	esac
	shift
done

[[ "$(uname -s)" == "Darwin" ]] || die "macOS releases are built on macOS"
for tool in go python3 xcrun security; do
	command -v "$tool" >/dev/null 2>&1 || die "needs $tool"
done
[[ -n "$VERSION" ]] || VERSION="$(config_value version)"
check_version "$VERSION"
case "$OUT_DIR" in /*) ;; *) OUT_DIR="$ROOT_DIR/$OUT_DIR" ;; esac
if [[ -n "$CHANGELOG" ]]; then
	[[ -f "$CHANGELOG" ]] || die "no changelog $CHANGELOG"
	CHANGELOG="$(cd "$(dirname "$CHANGELOG")" && pwd)/$(basename "$CHANGELOG")"
fi

((${#ARCHES[@]})) || ARCHES=(arm64 x64 universal)
PLATFORMS=()
for arch in "${ARCHES[@]}"; do
	case "$arch" in
	arm64) PLATFORMS+=(darwin/arm64) ;;
	x64 | amd64) PLATFORMS+=(darwin/amd64) ;;
	universal) PLATFORMS+=(darwin/universal) ;;
	*) die "unknown --arch $arch: arm64, x64 or universal" ;;
	esac
done

DEVELOPER_ID_APPLICATION="$(signing_identity)"
NOTARY_PROFILE=""
if $NOTARIZE; then NOTARY_PROFILE="$(notary_profile)"; fi
load_update_key
if $UPLOAD; then check_gh; fi

# The version, the changelog and the notarization go into mygo.json for this
# build only: notarizing would fail the ad hoc debug builds, which read it too.
CONFIG_BACKUP="$(mktemp)"
cp "$ROOT_DIR/mygo.json" "$CONFIG_BACKUP"
trap 'cp "$CONFIG_BACKUP" "$ROOT_DIR/mygo.json"; rm -f "$CONFIG_BACKUP"' EXIT
python3 -I - "$ROOT_DIR/mygo.json" "$VERSION" "$CHANGELOG" "$NOTARY_PROFILE" <<'EOF'
import json, sys
path, version, changelog, profile = sys.argv[1:]
with open(path) as f:
    config = json.load(f)
config["version"] = version
if changelog:
    config["updates"]["changelog"] = changelog
if profile:
    config.setdefault("macos", {})["notarize"] = {"keychainProfile": profile}
with open(path, "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
EOF

BUILD_ARGS=(-platform "$(
	IFS=,
	echo "${PLATFORMS[*]}"
)" -o "$OUT_DIR" -sign "$DEVELOPER_ID_APPLICATION")
$NOTARIZE || BUILD_ARGS+=(-skip-notarize)
$UPLOAD && BUILD_ARGS+=(-upload)

info "building ProxyGo $VERSION for macOS ${ARCHES[*]}, signed by $DEVELOPER_ID_APPLICATION"
go tool mygo build "${BUILD_ARGS[@]}"

# MyGo names disk images "<name> <version> <platform>.dmg", in a folder per
# platform; they are moved out beside those folders under the usual names.
for arch in "${ARCHES[@]}"; do
	case "$arch" in
	arm64) dmg="$OUT_DIR/darwin-arm64/ProxyGo $VERSION arm64.dmg" ;;
	x64 | amd64) dmg="$OUT_DIR/darwin-amd64/ProxyGo $VERSION amd64.dmg" arch=x64 ;;
	universal) dmg="$OUT_DIR/darwin-universal/ProxyGo $VERSION.dmg" ;;
	esac
	[[ -f "$dmg" ]] || die "expected $dmg after the build"
	if $NOTARIZE; then
		xcrun stapler validate "$dmg" >/dev/null || die "$dmg is not notarized"
	fi
	mv -f "$dmg" "$OUT_DIR/ProxyGo-$VERSION-$arch.dmg"
	info "$OUT_DIR/ProxyGo-$VERSION-$arch.dmg"
done
