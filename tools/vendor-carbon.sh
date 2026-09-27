#!/bin/bash
# vendor-carbon.sh: refresh assets/ from npm: Carbon's compiled styles, without
# their @font-face rules ( which load IBM Plex from IBM's CDN ), and the Plex
# weights the dashboard uses, so it works on clusters with no Internet access.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$tmp" && npm pack -q @carbon/styles @ibm/plex-sans @ibm/plex-mono >/dev/null && for f in *.tgz; do mkdir "${f%.tgz}" && tar -xzf "$f" -C "${f%.tgz}"; done)
styles=$(ls -d "$tmp"/carbon-styles-*/package)
python3 - "$styles/css/styles.min.css" assets/carbon.min.css <<'PY'
import re, sys
css = open(sys.argv[1]).read()
css, n = re.subn(r'@font-face\{[^}]*\}', '', css)
open(sys.argv[2], 'w').write(css)
print(f"removed {n} @font-face rules")
PY
cp "$styles/LICENSE" assets/LICENSE.carbon
echo "$(basename "$(dirname "$styles")")" > assets/VERSION.carbon
for f in IBMPlexSans-Regular IBMPlexSans-SemiBold; do cp "$tmp"/ibm-plex-sans-*/package/fonts/complete/woff2/$f.woff2 assets/fonts/; done
cp "$tmp"/ibm-plex-mono-*/package/fonts/complete/woff2/IBMPlexMono-Regular.woff2 assets/fonts/
cp "$(ls -d "$tmp"/ibm-plex-sans-*/package)/LICENSE.txt" assets/fonts/LICENSE.plex
