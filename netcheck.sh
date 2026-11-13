#!/usr/bin/env bash
# ============================================================================
#  netcheck.sh — одноразовая проверка сервера: КАНАЛ · IPv6 · связь из РФ и из-за рубежа
#  Запуск прямо на проверяемой машине (по SSH):   bash netcheck.sh
#  Проверить чужой хост:                          bash netcheck.sh 1.2.3.4
#  Порт для TCP-проверки из мира:                 PORT=443 bash netcheck.sh
#  Внешние сервисы (без ключей):
#    - гео: ipinfo.io → ip-api.com → ipwho.is (цепочка, пока кто-то не ответит)
#    - скорость: Ookla-сервер рядом (есть точки в РФ) → Selectel → mirror.yandex → Cloudflare
#    - связь по IPv4: check-host.net, при отказе — зонды Globalping
#    - связь по IPv6: зонды Globalping
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
CH_COLOR=1; [ -z "$B" ] && CH_COLOR=0

# ---------- Globalping: ping цели зондами РФ + мир (общий для v4-фолбэка и v6) ----------
gp_run(){ # $1 = цель (IP или имя), $2 = версия IP (4|6)
  GP_TARGET="$1" GP_VER="$2" CH_COLOR="$CH_COLOR" python3 - <<'PY'
import os,sys,re,json,time,urllib.request,urllib.error
T=os.environ["GP_TARGET"]; V=os.environ.get("GP_VER","6"); COL=os.environ.get("CH_COLOR")=="1"
def c(s,x): return f"\033[{x}m{s}\033[0m" if COL else s
API="https://api.globalping.io/v1/measurements"
def post(body):
    req=urllib.request.Request(API,data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","Accept":"application/json","User-Agent":"netcheck"})
    return json.load(urllib.request.urlopen(req,timeout=25))
def get(u):
    return json.load(urllib.request.urlopen(urllib.request.Request(u,
        headers={"Accept":"application/json","User-Agent":"netcheck"}),timeout=25))
opts={"packets":3}
# имя хоста (не литерал v4/v6) → форсим нужную версию IP при резолве
if ":" not in T and not re.fullmatch(r"[0-9.]+",T): opts["ipVersion"]=int(V)
body={"type":"ping","target":T,
      "locations":[{"country":"RU","limit":5},{"magic":"world","limit":10}],
      "measurementOptions":opts}
try:
    d=post(body)
except urllib.error.HTTPError as e:
    raw=e.read().decode(errors="replace")
    try: msg=json.loads(raw)["error"]["message"]
    except Exception: msg=" ".join(raw.split())[:200]
    print("  "+c("Globalping отклонил запрос: ","31")+msg); sys.exit(1)
except Exception as e:
    print("  "+c("Globalping недоступен: ","31")+str(e)); sys.exit(1)
mid=d.get("id")
if not mid: print("  "+c("нет ответа Globalping","31")); sys.exit(1)
r={}
for _ in range(24):
    try: r=get(f"{API}/{mid}")
    except Exception: r={}
    if r.get("status")!="in-progress": break
    time.sleep(1.5)
print(c(f"  Цель IPv{V}: {T}   ICMP-ping, зонды РФ + мир","2"))
RU=[]; AB=[]
for it in (r.get("results") or []):
    p=it.get("probe") or {}; res=it.get("result") or {}; st=res.get("stats") or {}
    row=(p.get("country") or "?", p.get("city") or "", st.get("loss"), st.get("avg"))
    (RU if row[0]=="RU" else AB).append(row)
def bucket(name,rs):
    if not rs:
        print(c(f"  ── {name} ──  (нет зондов)","2")); return (0,0)
    print(c(f"  ── {name} ──","1;35"))
    reach=0
    for cc,city,loss,avg in sorted(rs,key=lambda x:(x[0],x[1])):
        if loss is None:
            ps=c("нет данных".ljust(12),"31")
        else:
            pc="32" if loss==0 else ("33" if loss<100 else "31")
            ps=c((f"{loss:.0f}%loss" if loss else f"{(avg or 0):.0f}мс").ljust(12),pc)
            if loss<100: reach+=1
        print(f"    {(cc+' '+city)[:26].ljust(28)}{ps}")
    print(c(f"    итог: {reach}/{len(rs)} узлов видят хост по IPv{V}","2"))
    return (reach,len(rs))
rr=bucket("ИЗ РОССИИ",RU); ar=bucket("ИЗ-ЗА РУБЕЖА",AB)
def verdict(tag,reach,total):
    if total==0: return f"{tag} v{V}: нет зондов"
    if reach==0: return c(f"{tag} v{V}: НЕДОСТУПЕН (0/{total})","1;31")
    if reach<total: return c(f"{tag} v{V}: частично {reach}/{total}","1;33")
    return c(f"{tag} v{V}: доступен {reach}/{total}","1;32")
print()
print("  "+verdict("РФ",*rr))
print("  "+verdict("Зарубеж",*ar))
print(c(f"    measurement: {mid}","2"))
PY
}

# ============================================================================
sec "netcheck · $(date '+%Y-%m-%d %H:%M:%S %Z') · $(hostname 2>/dev/null)"

# ---------- 1. Идентификация машины ----------
sec "1 · КТО ЭТО (адрес, провайдер, гео)"
PUB4=$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || curl -4 -s --max-time 8 ifconfig.me 2>/dev/null)
PUB6=$(curl -6 -s --max-time 8 https://api64.ipify.org 2>/dev/null | grep -m1 ':' || true)
printf '  %sIPv4:%s %s\n' "$B" "$R" "${PUB4:-—}"
printf '  %sIPv6:%s %s\n' "$B" "$R" "${PUB6:-нет глобального IPv6}"
# гео: цепочка провайдеров — первый внятный ответ побеждает
GEO_LINE=""; GEO_SRC=""
if [ "$have_py" = 1 ] && [ -n "$PUB4" ]; then
  for GSRC in "https://ipinfo.io/${PUB4}/json" \
              "http://ip-api.com/json/${PUB4}?fields=status,country,city,org,isp" \
              "https://ipwho.is/${PUB4}"; do
    GJS=$(curl -s --max-time 8 "$GSRC" 2>/dev/null)
    [ -z "$GJS" ] && continue
    GEO_LINE=$(printf '%s' "$GJS" | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
if d.get("status")=="fail" or d.get("success") is False: sys.exit(1)
city=d.get("city") or ""
country=d.get("country") or d.get("country_code") or ""
if isinstance(country,dict): country=country.get("code") or ""
conn=d.get("connection") if isinstance(d.get("connection"),dict) else {}
org=d.get("org") or d.get("isp") or conn.get("org") or conn.get("isp") or ""
if not (city or country or org): sys.exit(1)
print((city or "?")+" "+(country or "?")+" / "+(org or "?"))' 2>/dev/null)
    [ -n "$GEO_LINE" ] && { GEO_SRC="$GSRC"; break; }
  done
fi
if [ -n "$GEO_LINE" ]; then
  printf '  %sГео :%s %s' "$B" "$R" "$GEO_LINE"
  case "$GEO_SRC" in https://ipinfo.io/*) ;; *) printf ' %s[%s]%s' "$D" "$(printf '%s' "$GEO_SRC" | sed 's|^https\?://||;s|/.*||')" "$R";; esac
  printf '\n'
else
  printf '  %sГео :%s %sне ответил ни один из ipinfo/ip-api/ipwho%s\n' "$B" "$R" "$YEL" "$R"
fi

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

# 2b. скорость: Ookla CLI -> speedtest-cli -> curl-замер
#     curl-замер: ближайший Ookla-сервер (в РФ свои точки, из РФ доступен) ->
#                 download: Selectel -> mirror.yandex -> Cloudflare; upload: Cloudflare
measure_down(){ # $1=url  ->  "speed http_code size"
  curl -o /dev/null -s --connect-timeout 6 --max-time 20 \
       -w '%{speed_download} %{http_code} %{size_download}' "$1" 2>/dev/null
}
printf '  %sСкорость:%s\n' "$B" "$R"
if need speedtest && speedtest --version </dev/null 2>/dev/null | grep -qi ookla; then
  speedtest --accept-license --accept-gdpr -f human-readable </dev/null 2>/dev/null | sed 's/^/    /'
elif need speedtest-cli; then
  speedtest-cli --simple </dev/null 2>/dev/null | sed 's/^/    /'
else
  SRV=""; CAND=""
  if [ "$have_py" = 1 ]; then
    CAND=$(curl -s --max-time 8 "https://www.speedtest.net/api/js/servers?engine=js&limit=5" 2>/dev/null \
      | python3 -c 'import sys,json
try:
 for s in json.load(sys.stdin)[:5]:
  h=s.get("host") or ""
  if h: print(h)
except Exception: pass' 2>/dev/null)
  fi
  for h in $CAND speedtest.procloud.ru:8080 speedtest.dme.fdcservers.net:8080; do
    [ "$(curl -o /dev/null -s --connect-timeout 4 --max-time 5 -w '%{http_code}' "http://$h/download?size=65536" 2>/dev/null)" = 200 ] \
      && { SRV=$h; break; }
  done
  dn=""; up=""
  if [ -n "$SRV" ]; then
    printf '    %s(speedtest-CLI не установлен — меряю curl-ом через Ookla-сервер %s)%s\n' "$D" "$SRV" "$R"
    read -r dn dcode dsize <<<"$(measure_down "http://$SRV/download?size=52428800")"
    [ "$dcode" = 200 ] || { printf '    %sdownload через %s: HTTP %s — ухожу на запасные%s\n' "$YEL" "$SRV" "${dcode:-нет ответа}" "$R"; dn=""; }
    read -r up ucode <<<"$(head -c 104857600 /dev/zero 2>/dev/null | curl -o /dev/null -s --connect-timeout 6 --max-time 20 \
         -w '%{speed_upload} %{http_code}' -X POST --data-binary @- "http://$SRV/speedtest/upload.php" 2>/dev/null)"
    [ "$ucode" = 200 ] || { printf '    %supload через %s: HTTP %s — ухожу на Cloudflare%s\n' "$YEL" "$SRV" "${ucode:-нет ответа}" "$R"; up=""; }
  else
    printf '    %s(Ookla-серверы не ответили — запасные зеркала)%s\n' "$D" "$R"
  fi
  if [ -z "$dn" ]; then
    for u in "https://speedtest.selectel.ru/100MB" \
             "https://mirror.yandex.ru/debian/ls-lR.gz" \
             "https://speed.cloudflare.com/__down?bytes=52428800"; do
      read -r dn dcode dsize <<<"$(measure_down "$u")"
      if [ "$dcode" = 200 ] && [ "${dsize%%.*}" -ge 1000000 ] 2>/dev/null; then
        printf '    %s(download: %s)%s\n' "$D" "$(printf '%s' "$u" | sed 's|^https\?://||;s|?.*||')" "$R"
        break
      fi
      printf '    %sdownload %s: HTTP %s, %s байт — пробую другой%s\n' "$YEL" \
        "$(printf '%s' "$u" | sed 's|^https\?://||;s|/.*||')" "${dcode:-нет ответа}" "${dsize:-0}" "$R"
      dn=""
    done
  fi
  if [ -z "$up" ]; then
    read -r up ucode <<<"$(head -c 104857600 /dev/zero 2>/dev/null | curl -o /dev/null -s --connect-timeout 6 --max-time 20 \
         -w '%{speed_upload} %{http_code}' -X POST --data-binary @- "https://speed.cloudflare.com/__up" 2>/dev/null)"
    if [ "$ucode" = 200 ]; then
      printf '    %s(upload: speed.cloudflare.com)%s\n' "$D" "$R"
    else
      printf '    %supload Cloudflare: HTTP %s — замерить не вышло%s\n' "$YEL" "${ucode:-нет ответа}" "$R"; up=0
    fi
  fi
  awk -v d="${dn:-0}" -v u="${up:-0}" -v cy="$CYA" -v rs="$R" 'BEGIN{
    printf "    Download: %s%.1f Мбит/с%s\n",cy,d*8/1e6,rs;
    printf "    Upload  : %s%.1f Мбит/с%s\n",cy,u*8/1e6,rs}'
fi

# 2c. MTU интерфейса + PMTU (пробы с DF до Яндекса — из РФ проходят всегда)
IF4=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
MTU_IF=$(cat "/sys/class/net/${IF4:-nope}/mtu" 2>/dev/null)
printf '  %sMTU:%s\n' "$B" "$R"
printf '    интерфейс %s: %s\n' "${IF4:-?}" "${MTU_IF:-?}"
PMTU=""
for s in 1472 1452 1420 1392 1352; do
  if ping -M do -c1 -W2 -s "$s" 77.88.8.8 >/dev/null 2>&1; then PMTU=$((s+28)); break; fi
done
if [ -n "$PMTU" ]; then
  if [ "$PMTU" -ge 1500 ]; then
    printf '    PMTU до Яндекса: %s%s%s\n' "$GRN" "$PMTU" "$R"
  else
    printf '    PMTU до Яндекса: %s%s%s %s(меньше 1500 — туннель или резка по пути)%s\n' "$YEL" "$PMTU" "$R" "$D" "$R"
  fi
else
  printf '    PMTU: %sне определился (DF-пинги не прошли или ping без -M)%s\n' "$YEL" "$R"
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

# ---------- 4. Связь из РФ и из-за рубежа по IPv4 ----------
sec "4 · СВЯЗЬ ИЗ РФ И ИЗ-ЗА РУБЕЖА (узлы check-host.net)"
# выбрать порт для TCP-проверки: PORT -> первый слушающий из 443/80/22 -> 443
if [ -z "$TCP_PORT" ]; then
  LISTEN=$(ss -H -tln 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un)
  for p in 443 80 22; do echo "$LISTEN" | grep -qx "$p" && { TCP_PORT=$p; break; }; done
  [ -z "$TCP_PORT" ] && TCP_PORT=443
fi
printf '  %sЦель:%s %s   %sICMP-ping + TCP:%s%s из ~30 стран\n' "$B" "$R" "${TARGET:-—}" "$D" "$R" "$TCP_PORT"

if [ "$have_py" != 1 ]; then
  printf '  %spython3 не найден — раздел «из РФ/зарубежа» пропущен.%s\n' "$RED" "$R"
elif [ -z "$TARGET" ]; then
  printf '  %sнет цели IPv4 — раздел пропущен.%s\n' "$YEL" "$R"
else
TARGET="$TARGET" TCP_PORT="$TCP_PORT" CH_COLOR="$CH_COLOR" python3 - <<'PY'
import os,sys,json,time,urllib.request,urllib.parse
T=os.environ["TARGET"]; PORT=os.environ["TCP_PORT"]; COL=os.environ.get("CH_COLOR")=="1"
def c(s,x): return f"\033[{x}m{s}\033[0m" if COL else s
API="https://check-host.net"
def get(u):
    req=urllib.request.Request(u,headers={"Accept":"application/json","User-Agent":"netcheck"})
    return json.load(urllib.request.urlopen(req,timeout=20))
def dispatch(kind,host):
    try: return get(f"{API}/check-{kind}?host={urllib.parse.quote(host)}&max_nodes=35")
    except Exception as e: return {"error":str(e)}
ping=dispatch("ping",T)
tcp =dispatch("tcp", f"{T}:{PORT}")
for tag,r in (("ping",ping),("tcp",tcp)):          # ошибки диспатча — наружу, а не в тишину
    if r.get("error"): print(c(f"  check-host {tag}: {r['error'][:140]}","31"))
nodes={}
for r in (ping,tcp):
    for n,info in (r.get("nodes") or {}).items(): nodes.setdefault(n,info)
if not nodes:
    print(c("  check-host не вернул ни одного узла.","33")); sys.exit(3)
def poll(rid):
    res={}
    if not rid: return res
    for _ in range(16):
        try: res=get(f"{API}/check-result/{rid}")
        except Exception: res={}
        if res and all(v is not None for v in res.values()): return res
        time.sleep(1.5)
    return res
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
CH_RC=$?
if [ "$CH_RC" = 3 ]; then
  printf '\n  %scheck-host не дал данных — проверяю IPv4 зондами Globalping:%s\n' "$YEL" "$R"
  gp_run "$TARGET" 4
fi
fi

# ---------- 5. Связь ПО IPv6 из РФ и из-за рубежа (Globalping) ----------
# check-host.net умеет только IPv4, поэтому v6-картину берём у зондов Globalping.
sec "5 · IPv6 ИЗ РФ И ИЗ-ЗА РУБЕЖА (зонды Globalping)"
# цель v6: env TARGET6 -> аргумент-IPv6 -> имя-хоста-аргумент -> свой глобальный v6
TARGET6="${TARGET6:-}"
if [ -z "$TARGET6" ]; then
  case "$TARGET_ARG" in
    *:*)        TARGET6="$TARGET_ARG" ;;              # аргумент — сам IPv6
    "")         TARGET6="${PUB6:-${V6ADDR%%/*}}" ;;   # свой хост → свой глобальный v6
    *[a-zA-Z]*) TARGET6="$TARGET_ARG" ;;              # аргумент — имя хоста (возьмём AAAA)
  esac
fi
if [ "$have_py" != 1 ]; then
  printf '  %spython3 не найден — IPv6-раздел пропущен.%s\n' "$RED" "$R"
elif [ -z "$TARGET6" ]; then
  printf '  %sНет цели IPv6%s: цель — IPv4-литерал без известного адреса v6.\n' "$YEL" "$R"
  printf '  %sЗапустите на самом сервере или задайте явно:%s TARGET6=2a0e:… bash netcheck.sh\n' "$D" "$R"
else
  gp_run "$TARGET6" 6
fi

sec "готово"
printf '  %sВсё выше — только чтение/замер, на машине ничего не менялось.%s\n\n' "$D" "$R"
