#!/usr/bin/env bash
# Renders the app icons Settings › General offers into internal/app/appicons:
# for each variant of assets/icon/variants.json, <name>.icns, which ProxyGo
# gives its bundle and Dock tile, and for those and the default icon
# (sunset), <name>.png, the picker's thumbnail. Run it after changing
# assets/icon; it needs Xcode 26 or later.
#
#   scripts/render-app-icons.sh
set -euo pipefail

for tool in xcrun python3 sips; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "render-app-icons.sh needs $tool." >&2
		exit 1
	fi
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
out="internal/app/appicons"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# compile renders the Icon Composer document $1 as the .icns of the systems
# before macOS 26, as mygo build does, into $2.
compile() {
	mkdir "$work/actool"
	if ! xcrun actool "$1" --compile "$work/actool" --output-format human-readable-text \
		--platform macosx --target-device mac --minimum-deployment-target 12.0 \
		--app-icon AppIcon --output-partial-info-plist "$work/actool/partial.plist" >"$work/actool.log" 2>&1 ||
		[[ ! -f "$work/actool/AppIcon.icns" ]]; then
		cat "$work/actool.log" >&2
		echo "actool could not compile $1 (it needs Xcode 26 or later)." >&2
		exit 1
	fi
	mv "$work/actool/AppIcon.icns" "$2"
	rm -rf "$work/actool"
}

# thumbnail writes the 128 px PNG of the .icns $1 to $2.
thumbnail() {
	sips -s format png -Z 128 "$1" --out "$2" >/dev/null
}

rm -rf "$out"
mkdir -p "$out"

echo "==> sunset"
compile assets/icon/AppIcon.icon "$work/sunset.icns"
thumbnail "$work/sunset.icns" "$out/sunset.png"

for name in $(python3 -I -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))))' assets/icon/variants.json); do
	echo "==> $name"
	# actool names the app icon after the document, which must be AppIcon.icon.
	mkdir "$work/$name"
	python3 -I scripts/lib/recolor-icon.py assets/icon/AppIcon.icon "$work/$name/AppIcon.icon" "$name"
	compile "$work/$name/AppIcon.icon" "$out/$name.icns"
	thumbnail "$out/$name.icns" "$out/$name.png"
done
echo "Rendered $root/$out"
