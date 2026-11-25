#!/bin/sh
# Builds httptap.app with its network extension, signs it with Developer ID, notarizes and staples it, and zips it.
#
#   build-app.sh <output.zip>
#
# No Apple account login is needed: the build is unsigned, then signed here with the Developer ID identity in the
# keychain and the Developer ID profiles and entitlements in signing/.
# HTTPTAP_SIGNING_IDENTITY picks the identity (default: "Developer ID Application").
# Notarization uses APPLE_ID, APPLE_APP_PASSWORD and APPLE_TEAM_ID when set, as in CI, and otherwise the notarytool
# keychain profile in NOTARY_PROFILE (default: persona-notary).
set -eu
output=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
identity=${HTTPTAP_SIGNING_IDENTITY:-Developer ID Application}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

xcodebuild build -project "$here/macos-redirector.xcodeproj" -scheme macos-redirector -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath "$work/build" CODE_SIGNING_ALLOWED=NO -quiet
app="$work/build/Build/Products/Release/httptap.app"
extension="$app/Contents/Library/SystemExtensions/com.stack1ng.simplehttptap.redirector.systemextension"
cp "$here/signing/redirector.provisionprofile" "$extension/Contents/embedded.provisionprofile"
cp "$here/signing/app.provisionprofile" "$app/Contents/embedded.provisionprofile"
codesign --force --timestamp --options runtime --entitlements "$here/signing/redirector.entitlements" -s "$identity" "$extension"
codesign --force --timestamp --options runtime --entitlements "$here/signing/app.entitlements" -s "$identity" "$app"
codesign --verify --strict --deep "$app"

ditto -c -k --keepParent "$app" "$work/submit.zip"
if [ -n "${APPLE_ID:-}" ]; then
  xcrun notarytool submit "$work/submit.zip" --apple-id "$APPLE_ID" --password "$APPLE_APP_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
else
  xcrun notarytool submit "$work/submit.zip" --keychain-profile "${NOTARY_PROFILE:-persona-notary}" --wait
fi
xcrun stapler staple "$app"
spctl -a -vv "$app"
ditto -c -k --keepParent "$app" "$output"
echo "built $output"
