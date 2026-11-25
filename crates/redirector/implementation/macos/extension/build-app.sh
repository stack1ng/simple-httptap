#!/bin/sh
# Builds httptap.app with its network extension, signs it with Developer ID, notarizes and staples it, and zips it.
#
#   build-app.sh <output.zip> [notary keychain profile]
#
# Signing is Xcode's automatic signing with -allowProvisioningUpdates: the archive is signed for development, and the
# Developer ID export re-signs it, turning the app-proxy-provider entitlement into app-proxy-provider-systemextension
# and making the Developer ID provisioning profiles. That is why the entitlements files say app-proxy-provider.
# Notarization uses a notarytool keychain profile (default: persona-notary), or NOTARY_KEY/NOTARY_KEY_ID/NOTARY_ISSUER
# for an App Store Connect API key, as CI has.
set -eu
output=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
profile=${2:-persona-notary}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

xcodebuild archive -project "$here/macos-redirector.xcodeproj" -scheme macos-redirector -configuration Release \
  -destination 'generic/platform=macOS' -archivePath "$work/httptap.xcarchive" -allowProvisioningUpdates -quiet
xcodebuild -exportArchive -archivePath "$work/httptap.xcarchive" -exportOptionsPlist "$here/ExportOptions.plist" \
  -exportPath "$work/export" -allowProvisioningUpdates -quiet
ditto -c -k --keepParent "$work/export/httptap.app" "$work/submit.zip"
if [ -n "${NOTARY_KEY:-}" ]; then
  xcrun notarytool submit "$work/submit.zip" --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
else
  xcrun notarytool submit "$work/submit.zip" --keychain-profile "$profile" --wait
fi
xcrun stapler staple "$work/export/httptap.app"
spctl -a -vv "$work/export/httptap.app"
ditto -c -k --keepParent "$work/export/httptap.app" "$output"
echo "built $output"
