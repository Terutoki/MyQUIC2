#!/bin/bash
# Interleaved A/B campaign: parent client vs HEAD client (SOCKS baseline) and
# HEAD with idle forward listeners, same HEAD server build.
set -u
cd /tmp/mq2-bench
source ./harness.sh
start_targets
: > "$LOGS/campaign.out"
for rep in 1 2 3; do
  case $rep in
    1) order="parent headA headB" ;;
    2) order="headB parent headA" ;;
    3) order="headA headB parent" ;;
  esac
  for arm in $order; do
    case $arm in
      parent) cfg=client-parent.toml ;;
      headA)  cfg=client-head-a.toml ;;
      headB)  cfg=client-head-b.toml ;;
    esac
    echo "=== CAMPAIGN arm=$arm rep=$rep start=$(date -u +%FT%TZ)" | tee -a "$LOGS/campaign.out"
    run_arm "$cfg" "$arm" "$rep" 2>&1 | tee -a "$LOGS/campaign.out"
  done
done
stop_targets
cleanup
echo "CAMPAIGN DONE $(date -u +%FT%TZ)" | tee -a "$LOGS/campaign.out"
