#!/bin/bash
# Rapid-fire DNS queries for TUI demo screenshot
# Mix of clean domains (allowed) and real malicious domains from feeds (blocked)

PORT=5353
HOST=127.0.0.1

# Clean domains — will show as ALLOWED (green)
CLEAN=(
  google.com
  youtube.com
  reddit.com
  stackoverflow.com
  github.com
  cloudflare.com
  amazon.com
  netflix.com
  twitter.com
  linkedin.com
  microsoft.com
  apple.com
  wikipedia.org
  rust-lang.org
  crates.io
  docs.rs
  mozilla.org
  fastly.com
  akamai.com
  nginx.com
  docker.com
  kubernetes.io
  grafana.com
  prometheus.io
  openai.com
  anthropic.com
  stripe.com
  twitch.tv
  discord.com
  slack.com
  figma.com
  vercel.com
  netlify.com
  aws.amazon.com
  cloud.google.com
  azure.microsoft.com
  npmjs.com
  pypi.org
  brew.sh
  archlinux.org
  ubuntu.com
  debian.org
  fedoraproject.org
  kernel.org
  torvalds.github.io
  news.ycombinator.com
  lobste.rs
  dev.to
  medium.com
  substack.com
)

# Real malicious domains from URLhaus/OpenPhish feeds + static blocklist
MALICIOUS=(
  triforgeix.chromeflack.in.net
  dyn-tidear.dockhype.in.net
  thifleet.dockhype.in.net
  gridfocus.cloudfloot.in.net
  zenmarken4.hostyard.in.net
  binscree.matchexact.in.net
  git33.matchexact.in.net
  patternprint.productter.in.net
  circuittraile.productter.in.net
  merlithex.tockentrue.in.net
  emberbroker.tockentrue.in.net
  gr0w-grid.paragonbloomera.in.net
  lumforgea.paragonbloomera.in.net
  capitalultra.quantumharbinger.in.net
  a-gwo.pages.dev
  a0coka3w.a5hsuper1or.ru
  a2-ghost-v3.columnasol.in.net
  abrababa.xyz
  a9350i8z.xyz
  aaa4b.com
  malware.example.com
  evil.example.com
  c2-relay.darkops.net
  payload-drop.malware-cdn.ru
  exfil-gateway.data-harvest.cn
  ransomware-drop.cryptolock.xyz
  botnet-controller.stormworm.cc
  trojan-callback.apt-group41.org
  dns-tunnel.covertchannel.top
  exploit-kit.angler-ek.net
)

QTYPES=(A AAAA MX TXT)

send_query() {
  local domain=$1
  local qtype=${QTYPES[$((RANDOM % ${#QTYPES[@]}))]}
  dig @$HOST -p $PORT $domain $qtype +short +timeout=1 +tries=1 &>/dev/null &
}

echo "Firing 150 queries at dnsink ($HOST:$PORT)..."
echo "Clean domains: ${#CLEAN[@]} | Malicious domains: ${#MALICIOUS[@]}"
echo ""

for i in $(seq 1 290); do
  # 60% clean, 40% malicious
  if (( RANDOM % 10 < 6 )); then
    domain=${CLEAN[$((RANDOM % ${#CLEAN[@]}))]}
  else
    domain=${MALICIOUS[$((RANDOM % ${#MALICIOUS[@]}))]}
  fi
  send_query "$domain"

  # Random delay 300-500ms to spread across 60s sparkline window
  sleep 0.$((RANDOM % 2 + 3))
done

# Final 10: scripted mix ending with red
echo "Final burst..."
send_query "github.com"
sleep 0.05
send_query "cloudflare.com"
sleep 0.05
send_query "malware.example.com"
sleep 0.05
send_query "rust-lang.org"
sleep 0.05
send_query "botnet-controller.stormworm.cc"
sleep 0.05
send_query "ransomware-drop.cryptolock.xyz"
sleep 0.05
send_query "google.com"
sleep 0.05
send_query "trojan-callback.apt-group41.org"
sleep 0.05
send_query "exploit-kit.angler-ek.net"
sleep 0.05
send_query "dns-tunnel.covertchannel.top"

wait
echo ""
echo "Done. 150 queries sent. Screenshot now."
