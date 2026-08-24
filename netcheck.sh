#!/usr/bin/env bash
# ============================================================================
#  netcheck.sh — одноразовая проверка сервера: КАНАЛ · IPv6 · связь из РФ и из-за рубежа
#  Запуск прямо на проверяемой машине (по SSH):   bash netcheck.sh
#  Проверить чужой хост:                          bash netcheck.sh 1.2.3.4
#  Порт для TCP-проверки из мира:                 PORT=443 bash netcheck.sh
#  Только один зависимый сервис — публичный API check-host.net (ключ не нужен).
#  Требуется: bash, curl, ping (+ping6 для IPv6), python3 (для разбора JSON).
#  Ничего не устанавливает и не меняет на машине — только читает и шлёт запросы.
# ============================================================================
set -uo pipefail
export LC_ALL=C

# ---------- цвета ----------
if { [ -t 1 ] || [ "${FORCE_COLOR:-}" = 1 ]; } && [ "${NO_COLOR:-}" != 1 ]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; CYA=$'\e[36m'; MAG=$'\e[35m'
else
  B=; D=; R=; RED=; GRN=; YEL=; BLU=; CYA=; MAG=
fi
ok(){ printf '%s' "${GRN}"; }; warn(){ printf '%s' "${YEL}"; }; bad(){ printf '%s' "${RED}"; }
line(){ printf '%s\n' "${D}────────────────────────────────────────────────────────────────────${R}"; }
sec(){ printf '\n%s\n' "${B}${CYA}▐ $* ${R}"; line; }

need(){ command -v "$1" >/dev/null 2>&1; }
have_py=0; need python3 && have_py=1
need curl || { echo "нужен curl"; exit 1; }

TARGET_ARG="${1:-}"
TCP_PORT="${PORT:-}"

# ============================================================================
sec "netcheck · $(date '+%Y-%m-%d %H:%M:%S %Z') · $(hostname 2>/dev/null)"

# ---------- 1. Идентификация машины ----------
sec "1 · КТО ЭТО (адрес, провайдер, гео)"
PUB4=$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || curl -4 -s --max-time 8 ifconfig.me 2>/dev/null)
PUB6=$(curl -6 -s --max-time 8 https://api64.ipify.org 2>/dev/null | grep -m1 ':' || true)
GEO=$(curl -4 -s --max-time 8 "https://ipinfo.io/${PUB4}/json" 2>/dev/null)
if [ -n "$GEO" ] && [ "$have_py" = 1 ]; then
  eval "$(printf '%s' "$GEO" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin)
 for k in ("city","region","country","org"):
  print("G_%s=%r"%(k,d.get(k,"")))
except: pass')"
fi
printf '  %sIPv4:%s %s\n' "$B" "$R" "${PUB4:-—}"
printf '  %sIPv6:%s %s\n' "$B" "$R" "${PUB6:-нет глобального IPv6}"
printf '  %sГео :%s %s %s / %s\n' "$B" "$R" "${G_city:-?}" "${G_country:-?}" "${G_org:-?}"

# цель проверки «из мира»: по умолчанию свой IPv4
TARGET="${TARGET_ARG:-$PUB4}"
[ -z "$TARGET" ] && { echo "${RED}не удалось определить публичный IPv4${R}"; }

# ---------- 2. КАНАЛ ----------
sec "2 · КАНАЛ (скорость, задержки, MTU)"
# 2a. пинги до якорей
declare -A ANCHOR=( [Cloudflare_1.1.1.1]=1.1.1.1 [Google_8.8.8.8]=8.8.8.8 [Yandex_RU_77.88.8.8]=77.88.8.8 [Hetzner_DE]=88.198.248.254 )
printf '  %sЗадержки:%s\n' "$B" "$R"
for name in Cloudflare_1.1.1.1 Google_8.8.8.8 Yandex_RU_77.88.8.8 Hetzner_DE; do
  ip=${ANCHOR[$name]}
  out=$(ping -c3 -w4 "$ip" 2>/dev/null)
  r=$(printf '%s' "$out" | awk -F'/' '/rtt|round-trip/{printf "%.1f мс",$5}')
  loss=$(printf '%s' "$out" | sed -n 's/.*[, ]\([0-9]*\)% packet loss.*/\1/p' | head -1)
  [ -z "$loss" ] && loss=100
  lc=$GRN; [ "$loss" != 0 ] && lc=$YEL; [ "$loss" = 100 ] && lc=$RED
  printf '    %-26s %s%-9s%s  loss %s%3s%%%s\n' "${name//_/ }" "$CYA" "${r:-—}" "$R" "$lc" "$loss" "$R"
done
# 2b. скорость: Ookla speedtest -> speedtest-cli -> curl-бенч Cloudflare
printf '  %sСкорость:%s\n' "$B" "$R"
if need speedtest && speedtest --version 2>/dev/null | grep -qi ookla; then
  speedtest --accept-license --accept-gdpr -f human-readable 2>/dev/null | sed 's/^/    /'
elif need speedtest-cli; then
  speedtest-cli --simple 2>/dev/null | sed 's/^/    /'
else
  printf '    %s(Ookla speedtest не установлен — меряю curl-ом с Cloudflare)%s\n' "$D" "$R"
  dn=$(curl -4 -o /dev/null -s --max-time 25 -w '%{speed_download}' \
       "https://speed.cloudflare.com/__down?bytes=52428800" 2>/dev/null)
  up=$(head -c 26214400 /dev/zero 2>/dev/null | curl -4 -o /dev/null -s --max-time 25 -w '%{speed_upload}' \
       -X POST --data-binary @- "https://speed.cloudflare.com/__up" 2>/dev/null)
  awk -v d="${dn:-0}" -v u="${up:-0}" -v cy="$CYA" -v rs="$R" 'BEGIN{
    printf "    Download: %s%.1f Мбит/с%s\n",cy,d*8/1e6,rs;
    printf "    Upload  : %s%.1f Мбит/с%s\n",cy,u*8/1e6,rs}'
fi

# ---------- 3. IPv6 ----------
sec "3 · IPv6 (стек, исходящий, входящий из мира)"
V6ADDR=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print $2}' | grep -v '^fe80' | head -1)
V6ROUTE=$(ip -6 route show default 2>/dev/null | head -1)
if [ -z "$V6ADDR" ]; then
  printf '  %sЛокально: глобального IPv6-адреса НЕТ — сервер без IPv6.%s\n' "$RED" "$R"
else
  printf '  %sЛокальный адрес:%s %s\n' "$B" "$R" "$V6ADDR"
  printf '  %sМаршрут по умолч.:%s %s\n' "$B" "$R" "${V6ROUTE:-нет!}"
  # исходящий
  o6=0
  if ping6 -c2 -w4 2606:4700:4700::1111 >/dev/null 2>&1 || ping -6 -c2 -w4 2606:4700:4700::1111 >/dev/null 2>&1; then o6=1; fi
  my6=$(curl -6 -s --max-time 8 https://ipv6.icanhazip.com 2>/dev/null)
  if [ "$o6" = 1 ] || [ -n "$my6" ]; then
    printf '  %sИсходящий v6:%s %sРАБОТАЕТ%s (виден как %s)\n' "$B" "$R" "$GRN" "$R" "${my6:-ok}"
  else
    printf '  %sИсходящий v6:%s %sНЕ работает (адрес есть, но пакеты не ходят)%s\n' "$B" "$R" "$RED" "$R"
  fi
fi

# ---------- 4+5. Связь из РФ и из-за рубежа (check-host.net) ----------
sec "4 · СВЯЗЬ ИЗ РФ И ИЗ-ЗА РУБЕЖА (узлы check-host.net)"
# выбрать порт для TCP-проверки: PORT -> первый слушающий из 443/80/22 -> 443
if [ -z "$TCP_PORT" ]; then
  LISTEN=$(ss -H -tln 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un)
  for p in 443 80 22; do echo "$LISTEN" | grep -qx "$p" && { TCP_PORT=$p; break; }; done
  [ -z "$TCP_PORT" ] && TCP_PORT=443
fi
printf '  %sЦель:%s %s   %sICMP-ping + TCP:%s%s из ~30 стран\n' "$B" "$R" "$TARGET" "$D" "$R" "$TCP_PORT"

if [ "$have_py" != 1 ]; then
  printf '  %spython3 не найден — раздел «из РФ/зарубежа» пропущен.%s\n' "$RED" "$R"
else
CH_COLOR=1; [ -z "$B" ] && CH_COLOR=0
TARGET="$TARGET" TCP_PORT="$TCP_PORT" CH_COLOR="$CH_COLOR" python3 - <<'PY'
import os,sys,json,time,urllib.request
T=os.environ["TARGET"]; PORT=os.environ["TCP_PORT"]; COL=os.environ.get("CH_COLOR")=="1"
if not T: print("  нет цели"); sys.exit()
def c(s,x): return f"\033[{x}m{s}\033[0m" if COL else s
API="https://check-host.net"
def get(u):
    req=urllib.request.Request(u,headers={"Accept":"application/json","User-Agent":"netcheck"})
    return json.load(urllib.request.urlopen(req,timeout=20))
def dispatch(kind,host):
    try: return get(f"{API}/check-{kind}?host={urllib.parse.quote(host)}&max_nodes=35")
    except Exception as e: return {"error":str(e)}
import urllib.parse
ping=dispatch("ping",T)
tcp =dispatch("tcp", f"{T}:{PORT}")
nodes={}
for r in (ping,tcp):
    for n,info in (r.get("nodes") or {}).items(): nodes.setdefault(n,info)
def poll(rid):
    if not rid: return {}
    for _ in range(16):
        try: res=get(f"{API}/check-result/{rid}")
        except Exception: res={}
        if res and all(v is not None for v in res.values()): return res
        time.sleep(1.5)
    return res if 'res' in dir() else {}
pres=poll(ping.get("request_id")); tres=poll(tcp.get("request_id"))
def ping_stat(v):
    try:
        atts=v[0]
        okc=sum(1 for a in atts if isinstance(a,list) and a and a[0]=="OK")
        tot=len(atts) or 1
        rtts=[a[1] for a in atts if isinstance(a,list) and len(a)>=2 and a[0]=="OK"]
        avg=sum(rtts)/len(rtts)*1000 if rtts else None
        return okc,tot,avg
    except: return 0,1,None
def tcp_stat(v):
    try:
        d=v[0]
        if isinstance(d,dict) and "time" in d: return True, d["time"]*1000
        return False,None
    except: return False,None
rows=[]
for n,info in nodes.items():
    cc=(info[0] if info else "?"); city=(info[2] if info and len(info)>2 else info[1] if info else "")
    country=(info[1] if info and len(info)>1 else "")
    ok,tot,rtt=ping_stat(pres.get(n)) if pres.get(n) is not None else (0,1,None)
    tok,trtt=tcp_stat(tres.get(n)) if tres.get(n) is not None else (False,None)
    rows.append((cc,country,city,ok,tot,rtt,tok,trtt))
RU={"ru"}
def bucket(name,rs):
    if not rs:
        print("  (нет данных)"); return (0,0)
    print(c(f"  ── {name} ──","1;35"))
    print(c("    страна/город".ljust(30)+"ping        TCP:"+PORT,"2"))
    reach=0
    for cc,country,city,ok,tot,rtt,tok,trtt in sorted(rs,key=lambda x:(x[0],x[2])):
        loss=100*(tot-ok)//tot
        pc = "32" if loss==0 else ("33" if loss<100 else "31")
        ps = c(f"{('%d%%loss'%loss) if loss else ('%.0fмс'%(rtt or 0))}".ljust(9),pc)
        tc = "32" if tok else "31"
        ts = c(("open %.0fмс"%trtt) if tok else "закрыт/фильтр",tc)
        flag=cc.upper()
        loc=f"{flag} {city}"[:28]
        print(f"    {loc.ljust(30)}{ps}  {ts}")
        if loss<100 or tok: reach+=1
    print(c(f"    итог: {reach}/{len(rs)} узлов видят хост","2"))
    return (reach,len(rs))
ru=[r for r in rows if r[0] in RU]
ab=[r for r in rows if r[0] not in RU]
rr=bucket("ИЗ РОССИИ",ru)
ar=bucket("ИЗ-ЗА РУБЕЖА",ab)
pl=ping.get("permanent_link") or ""
if pl: print(c(f"    отчёт: {pl}","2"))
# вердикт в конце
def verdict(tag,reach,total):
    if total==0: return f"{tag}: нет узлов"
    if reach==0: return c(f"{tag}: НЕДОСТУПЕН (0/{total})","1;31")
    if reach<total: return c(f"{tag}: частично {reach}/{total}","1;33")
    return c(f"{tag}: доступен {reach}/{total}","1;32")
print()
print("  "+verdict("РФ",*rr))
print("  "+verdict("Зарубеж",*ar))
PY
fi

sec "готово"
printf '  %sВсё выше — только чтение/замер, на машине ничего не менялось.%s\n\n' "$D" "$R"
