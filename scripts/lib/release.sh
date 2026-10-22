# Shared by build-mac-release.sh and publish.sh; source it.

die() {
	printf '%s: %s\n' "$(basename "$0")" "$*" >&2
	exit 1
}
info() { printf '==> %s\n' "$*"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# check_version fails unless $1 looks like 1.2.3.
check_version() {
	[[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "the version must look like 1.2.3, not $1"
}

# config_value prints the value in mygo.json at the dotted keys $1, as in
# "version" or "updates.github".
config_value() {
	python3 -I -c '
import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value[key]
print(value)' "$ROOT_DIR/mygo.json" "$1"
}

# signing_identity prints DEVELOPER_ID_APPLICATION, or the keychain's one
# Developer ID Application identity when it is not set, and fails unless the
# keychain has it.
signing_identity() {
	local identities found id="${DEVELOPER_ID_APPLICATION:-}"
	identities="$(security find-identity -v -p codesigning)"
	if [[ -z "$id" ]]; then
		found="$(printf '%s\n' "$identities" | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | sort -u)"
		[[ -n "$found" ]] || die "no Developer ID Application identity in the keychain; set DEVELOPER_ID_APPLICATION"
		[[ "$(printf '%s\n' "$found" | wc -l)" -eq 1 ]] ||
			die "several Developer ID identities; set DEVELOPER_ID_APPLICATION to one of: $(printf '%s\n' "$found" | paste -sd ';' - | sed 's/;/; /g')"
		id="$found"
	fi
	printf '%s\n' "$identities" | grep -qF "\"$id\"" || die "no signing identity \"$id\" in the keychain"
	printf '%s\n' "$id"
}

# notary_profile prints the notarytool keychain profile, PROXYGO_NOTARY_PROFILE
# or "ProxyGo", and fails unless it works.
notary_profile() {
	local profile="${PROXYGO_NOTARY_PROFILE:-ProxyGo}"
	xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1 ||
		die "the notarytool keychain profile \"$profile\" doesn't work; make it with xcrun notarytool store-credentials"
	printf '%s\n' "$profile"
}

# load_update_key exports MYGO_UPDATER_PRIVATE_KEY, which signs updates, from
# the file PROXYGO_UPDATE_KEY names (by default the one `go tool mygo keygen`
# wrote for ProxyGo) unless it is set.
load_update_key() {
	[[ -n "${MYGO_UPDATER_PRIVATE_KEY:-}" ]] && { export MYGO_UPDATER_PRIVATE_KEY; return; }
	local file="${PROXYGO_UPDATE_KEY:-$HOME/Library/Application Support/mygo/update-keys/ProxyGo/mygo-update.key}"
	[[ -f "$file" ]] || die "no update signing key at $file; set PROXYGO_UPDATE_KEY or MYGO_UPDATER_PRIVATE_KEY"
	MYGO_UPDATER_PRIVATE_KEY="$(<"$file")"
	export MYGO_UPDATER_PRIVATE_KEY
}

# check_gh fails unless the GitHub CLI is there to upload with, signed in.
check_gh() {
	command -v gh >/dev/null 2>&1 || die "uploads need the GitHub CLI, gh"
	gh auth status >/dev/null 2>&1 || [[ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]] || die "uploads need gh auth login, or GH_TOKEN"
}
