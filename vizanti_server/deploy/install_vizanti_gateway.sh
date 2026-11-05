#!/bin/bash
# vizanti 게이트웨이 로봇 설치 스크립트 (로봇에서 sudo 로 실행)
#
#   sudo bash install_vizanti_gateway.sh                # 정식 설치
#   sudo bash install_vizanti_gateway.sh firewall-only  # Phase 0: 3.3.0 로봇 임시 잠금 (5000-5003 전부 외부 차단)
#   sudo bash install_vizanti_gateway.sh uninstall      # 유닛·방화벽 제거 (등록 데이터/인증서/설정 파일은 보존)
#
#   sudo bash install_vizanti_gateway.sh nif-open                  # network-iface 51231/51233 LAN 노출 (롤백 경로)
#   sudo bash install_vizanti_gateway.sh nif-lock [--force]        # 51231/51233 루프백 전용 (LAN 은 :5000 /api 경유)
#   sudo bash install_vizanti_gateway.sh host-guard observe|enforce|off
#   sudo bash install_vizanti_gateway.sh host-guard reload|status|survey [since]
#        bash install_vizanti_gateway.sh host-guard render [observe|enforce] [open|lock]   # 미리보기 (root 불필요)
#   sudo bash install_vizanti_gateway.sh ssh-keyonly apply|confirm|revert|status        # ssh-keyonly.sh 에 위임
#
# 정식 설치가 하는 일
#   - 전제 검사: 게이트웨이 바이너리, python3-cryptography/python3-openssl exporter API, 포트 5000, nav launch
#   - TLS 자가서명 인증서 생성 (로봇별, 10년) — 최초 등록 전 독립 경로로 지문 확인
#   - vizanti-firewall.service + vizanti-gateway.service 설치/검증/기동 (재부팅 영속). 재실행(업그레이드·롤백)도
#     방화벽 룰을 다시 적용하고 게이트웨이를 재시작한 뒤 /gw/info 의 version 이 설치본과 같은지 확인
#   - /etc/vizanti/nif.mode(없을 때만 lock), /etc/vizanti/host-guard.conf(없을 때만 MODE=enforce) 생성 후
#     vizanti-host-guard.service 설치·적용 — 첫 설치부터 LAN 우회 포트 차단 (lock + enforce)
#   - ufw 활성 로봇이면 5000/tcp allow
#   - 신규 인증은 network-iface 단일 권위. 게이트웨이는 페어링 코드/기기 목록을 발급·저장하지 않음
#
# 전제: colcon 설치로 /opt/robot/rgt_ws/common/lib/vizanti_server/vizanti_gateway.py 가 존재하고,
#       /opt/robot/rgt_ws/navigation/share/rgt_nav3_launch/launch/vizanti.launch.py 가 3.4.0 버전
#       (vizanti_server launch include) 으로 교체돼 있어야 함.
#       구버전 nav launch(flask 0.0.0.0:5000) 가 떠 있거나, 어느 그룹·~rgt/test_ws 에든 구버전 사본이 있으면 설치가 중단됨.

set -euo pipefail

RGT_WS=/opt/robot/rgt_ws               # 릴리스 트리(rgt_ws_X.Y.Z) 링크. 그룹별 오버레이: common, navigation, ...
WS_ROOT=$RGT_WS/common
GW_BIN=$WS_ROOT/lib/vizanti_server/vizanti_gateway.py
NAV_LAUNCH=$RGT_WS/navigation/share/rgt_nav3_launch/launch/vizanti.launch.py
SHARE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW_USER=rgt
GW_HOME=/home/$GW_USER
DATA_DIR=$GW_HOME/.rgt_data/vizanti_gateway
UNIT_DST=/etc/systemd/system/vizanti-gateway.service
FW_UNIT_DST=/etc/systemd/system/vizanti-firewall.service
NFT_DST=/etc/vizanti-firewall.nft
UFW_MARKER=$DATA_DIR/.ufw_allow_added

# nif 모드 + 호스트 가드. RGT_VIZANTI_ETC / RGT_SYSTEMD_UNIT_DIR 는 시험용 재정의 — 운영에서는 설정하지 말 것
# (유닛의 ExecStart 는 /etc/vizanti/firewall-host.nft 고정)
VZ_ETC=${RGT_VIZANTI_ETC:-/etc/vizanti}
NIF_MODE_FILE=$VZ_ETC/nif.mode          # network-iface(http_exposure.py) 가 기동 시 읽음: open | lock
HG_CONF=$VZ_ETC/host-guard.conf
HG_NFT=$VZ_ETC/firewall-host.nft        # 렌더 결과 (vizanti-host-guard.service 가 적용)
HG_TEMPLATE=$SHARE_DIR/firewall-host.nft.in
HG_UNIT=vizanti-host-guard.service
HG_UNIT_DST=${RGT_SYSTEMD_UNIT_DIR:-/etc/systemd/system}/$HG_UNIT
HG_DEFAULT_HW_NETS="10.0.0.0/24 192.168.158.0/24"   # MCU UDP 링크, LiDAR

die() { echo "오류: $*" >&2; exit 1; }

usage() {
    sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

verify_unit() {   # systemd-analyze verify 는 경고만으로는 exit 0 이므로 유닛 경로로 필터링
    # 출력을 먼저 받아 둠: "| grep -q" 는 일찍 끝나 앞 명령이 SIGPIPE 를 받으면 pipefail 로 판정이 뒤집힐 수 있음
    local msgs
    msgs=$(systemd-analyze verify "$1" 2>&1 | grep -F "$(basename "$1")" || true)
    if grep -qiE 'Unknown key|Failed|error' <<< "$msgs"; then
        echo "오류: $1 유닛 검증 실패" >&2
        printf '%s\n' "$msgs" >&2
        exit 1
    fi
}

install_firewall() {   # $1 = nft 룰 파일 경로 (설치본), $2 = gateway(5000 허용) | phase0(5000-5003 전부 차단)
    local chain
    cp "$1" "$NFT_DST"
    cp "$SHARE_DIR/vizanti-firewall.service" "$FW_UNIT_DST"
    verify_unit "$FW_UNIT_DST"
    nft -c -f "$NFT_DST" || { echo "오류: $NFT_DST 문법/커널 검사 실패" >&2; exit 1; }
    # 과거 설치본이 /etc/nftables.conf 에 include 를 남겼다면 제거 (stock nftables.service 는 쓰지 않음)
    sed -i '\#include "/etc/vizanti-firewall.nft"#d' /etc/nftables.conf 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable vizanti-firewall.service
    # oneshot+RemainAfterExit: 이미 active 면 start(enable --now)는 아무것도 하지 않음 -> ExecReload(nft -f, 한 트랜잭션), 아니면 start
    systemctl reload-or-restart vizanti-firewall.service \
        || { echo "오류: vizanti-firewall.service 적용 실패 (journalctl -u vizanti-firewall)" >&2; exit 1; }
    # 테이블 존재만으로는 이전 룰(Phase 0 <-> 정식)이 남아 있어도 통과하므로 내용으로 판정
    chain=$(nft list chain inet vizanti_guard input 2>/dev/null || true)
    [[ -n $chain ]] || { echo "오류: vizanti_guard 테이블이 적용되지 않음" >&2; exit 1; }
    case $2 in
        gateway) grep -qF 'comment "allow_gateway"' <<< "$chain" \
                     || { echo "오류: 커널의 vizanti_guard 에 5000 허용(allow_gateway)이 없음 — 정식 룰이 적용되지 않음" >&2; exit 1; } ;;
        phase0)  ! grep -qF 'comment "allow_gateway"' <<< "$chain" \
                     || { echo "오류: 커널의 vizanti_guard 에 5000 허용(allow_gateway)이 남아 있음 — Phase 0 룰이 적용되지 않음" >&2; exit 1; } ;;
        *)       echo "오류: install_firewall: 알 수 없는 종류 '$2'" >&2; exit 1 ;;
    esac
    if grep -q '^Status: active' <<< "$(ufw status 2>/dev/null || true)"; then
        ufw allow 5000/tcp comment 'vizanti gateway' >/dev/null
        mkdir -p "$(dirname "$UFW_MARKER")" && touch "$UFW_MARKER"
        echo "[fw] ufw 활성 감지 -> 5000/tcp allow 추가"
    fi
}

# ================================================================ /etc/vizanti 설정 파일
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }

conf_get() {   # $1=KEY $2=기본값. host-guard.conf 를 셸로 source 하지 않음: KEY=VALUE 줄만 읽음 (마지막 값 우선)
    local key=$1 val="" found=0 line re_dq='^"([^"]*)"' re_sq="^'([^']*)'"
    if [[ -f $HG_CONF ]]; then
        while IFS= read -r line || [[ -n $line ]]; do
            line=${line%$'\r'}
            if [[ $line =~ ^[[:space:]]*${key}[[:space:]]*=(.*)$ ]]; then
                val=${BASH_REMATCH[1]}
                found=1
            fi
        done < "$HG_CONF"
    fi
    if (( ! found )); then
        printf '%s' "$2"
        return 0
    fi
    val=$(trim "$val")
    if [[ $val =~ $re_dq || $val =~ $re_sq ]]; then
        val=${BASH_REMATCH[1]}
    else
        val=${val%%#*}
    fi
    trim "$val"
}

conf_set() {   # $1=KEY $2=VALUE(단어). 해당 줄만 교체(없으면 추가) — 주석·다른 줄 보존, 원자적 교체
    local key=$1 val=$2 tmp
    tmp=$(mktemp "$VZ_ETC/.host-guard.conf.XXXXXX")
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$HG_CONF"; then
        sed -E "s/^[[:space:]]*${key}[[:space:]]*=.*$/${key}=${val}/" "$HG_CONF" > "$tmp"
    else
        cat "$HG_CONF" > "$tmp"
        printf '%s=%s\n' "$key" "$val" >> "$tmp"
    fi
    chmod 644 "$tmp"
    mv -f "$tmp" "$HG_CONF"
}

write_default_hg_conf() {
    local tmp
    tmp=$(mktemp "$VZ_ETC/.host-guard.conf.XXXXXX")
    cat > "$tmp" <<EOF
# RGT host guard 설정 — install_vizanti_gateway.sh 가 읽어 $HG_NFT 로 렌더한다.
# 고친 뒤 반영:  sudo bash install_vizanti_gateway.sh host-guard reload   (미리보기: host-guard render)
# 셸로 source 되지 않음: KEY=VALUE 줄만 인식. 목록은 공백 또는 쉼표로 구분.

# observe | enforce | off   (host-guard observe|enforce|off 명령이 이 줄을 바꾼다)
MODE=enforce

# 로봇 하드웨어망 (MCU UDP 링크, LiDAR): 이 출발지는 그 대역이 연결된 NIC 로 들어올 때 모든 포트 허용. IPv6 CIDR 도 가능
# 로봇에 없는 대역(예: LiDAR NIC 없는 기종의 192.168.158.0/24)은 빼 둘 것
HW_NETS="$HG_DEFAULT_HW_NETS"
# no  = 렌더(reload) 할 때 대역마다 직접 연결 경로가 있고 그 대역 주소를 가진 NIC 를 찾아 iifname 으로 고정 (다른 NIC 로
#       들어온 위조 출발지는 불허). 렌더 순간 NIC 가 없으면 지금 적용된 바인딩을 유지, 그것도 없으면 신뢰하지 않음(렌더 경고).
#       NIC 이름·주소가 바뀌면 host-guard reload (host-guard status 가 커널 룰과 비교해 경고)
# yes = 패킷마다 커널 경로 검사 (fib saddr . iif: 출발지로 가는 최선 경로의 NIC 로 들어온 것만, 렌더 시점 기본 경로 NIC 제외).
#       HW 대역의 직접 경로가 없으면 그 출발지로 가는 다른 경로(VPN 등)의 NIC 로 온 위조가 통과
HW_NETS_STRICT=no

# 추가로 열 포트 (예: "5900 8080-8090"). observe 로그(rgt-guard)로 확인된 정당한 호출만 추가할 것
EXTRA_TCP_PORTS=""
EXTRA_UDP_PORTS=""

# 통째로 신뢰할 인터페이스 (예: "tailscale0" — rgt_remote). 와일드카드는 끝에만 ("tun*")
TRUST_IFACES=""
EOF
    chmod 644 "$tmp"
    mv -f "$tmp" "$HG_CONF"
}

write_nif_mode() {   # $1 = open|lock — network-iface 가 rgt 사용자로 읽으므로 0644 (디렉터리 0755)
    local tmp
    tmp=$(mktemp "$VZ_ETC/.nif.mode.XXXXXX")
    printf '%s\n' "$1" > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$NIF_MODE_FILE"
}

ensure_vizanti_etc() {   # 없을 때만 기본값 생성 (재설치가 운영자 선택을 덮지 않음)
    install -d -m 755 "$VZ_ETC"
    if [[ ! -f $NIF_MODE_FILE ]]; then
        write_nif_mode lock
        echo "[nif] $NIF_MODE_FILE = lock (기본: 51231/51233 루프백 전용)"
    fi
    if [[ ! -f $HG_CONF ]]; then
        write_default_hg_conf
        echo "[guard] $HG_CONF 기본값 생성 (MODE=enforce: 기본 거부)"
    fi
}

nif_mode() {   # network-iface 와 같은 해석: 없음 -> open, 알 수 없는 내용 -> lock(fail-closed)
    local w
    if [[ ! -e $NIF_MODE_FILE ]]; then
        echo open
        return 0
    fi
    w=$(tr -d '[:space:]' < "$NIF_MODE_FILE" 2>/dev/null || true)
    case $w in
        open|lock) echo "$w" ;;
        *) echo "경고: $NIF_MODE_FILE 내용 '$w' 을(를) 알 수 없음 — network-iface 처럼 lock 으로 간주" >&2
           echo lock ;;
    esac
}

hg_mode() {
    local m
    m=$(conf_get MODE observe)
    case $m in
        observe|enforce|off) echo "$m" ;;
        *) die "$HG_CONF: MODE='$m' (observe|enforce|off 중 하나여야 함)" ;;
    esac
}

# ================================================================ host guard: 검증·렌더
split_list() {   # 공백/쉼표 목록 -> 한 줄에 하나 (글로브 확장 없음)
    local -a arr=()
    read -r -a arr <<< "${1//,/ }" || true
    (( ${#arr[@]} )) && printf '%s\n' "${arr[@]}"
    return 0
}

join_list() { local IFS=,; local s="$*"; printf '%s' "${s//,/, }"; }

norm_port() {   # "80" / "8000-8100" -> 정규화 (앞자리 0 제거). 범위 밖이면 실패
    local a b
    [[ $1 =~ ^([0-9]{1,5})(-([0-9]{1,5}))?$ ]] || return 1
    a=$((10#${BASH_REMATCH[1]}))
    b=$((10#${BASH_REMATCH[3]:-${BASH_REMATCH[1]}}))
    (( a >= 1 && b <= 65535 && a <= b )) || return 1
    if (( a == b )); then printf '%s' "$a"; else printf '%s-%s' "$a" "$b"; fi
}

port_in() {   # $1=포트, $2...=norm_port 결과 목록 ("80" / "8000-8100"). 하나라도 포함하면 참
    local p=$1 e
    shift
    for e in "$@"; do
        (( p >= ${e%-*} && p <= ${e#*-} )) && return 0
    done
    return 1
}

net_family() {   # IPv4/IPv6 주소·CIDR 형식 검사 -> 4 / 6 (의미 검증은 nft -c 가 최종)
    local n=$1
    if [[ $n =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$ ]]; then
        (( 10#${BASH_REMATCH[1]} <= 255 && 10#${BASH_REMATCH[2]} <= 255 &&
           10#${BASH_REMATCH[3]} <= 255 && 10#${BASH_REMATCH[4]} <= 255 )) || return 1
        [[ -z ${BASH_REMATCH[6]} ]] || (( 10#${BASH_REMATCH[6]} <= 32 )) || return 1
        printf 4
    elif [[ $n == *:* && $n =~ ^[0-9A-Fa-f:.]+(/([0-9]{1,3}))?$ ]]; then
        [[ -z ${BASH_REMATCH[2]} ]] || (( 10#${BASH_REMATCH[2]} <= 128 )) || return 1
        printf 6
    else
        return 1
    fi
}

# ip -o route 한 줄 -> "접두사길이 인터페이스". default·게이트웨이 경유(via)·다중 경로·unicast 아닌 경로는 버림
# (default 나 LAN 쪽 게이트웨이 경로에 묶으면 LAN NIC 을 신뢰하게 되어 위조 차단이 의미 없어짐)
HW_ROUTE_AWK='
    $1 == "default" || $1 ~ /^(unreachable|blackhole|prohibit|throw|local|broadcast|anycast|multicast|nat)$/ { next }
    /[[:space:]]via[[:space:]]|nexthop/ { next }
    {
        for (i = 2; i < NF; i++)
            if ($i == "dev") { p = index($1, "/"); print (p ? substr($1, p + 1) : (fam == 6 ? 128 : 32)) + 0, $(i + 1); next }
    }'

hw_net_devs() {   # $1=HW_NETS 항목 $2=4|6 -> 그 대역이 직접 연결된 인터페이스 (한 줄에 하나, 지금 main 라우팅 표 기준)
    # 항목을 감싸는 경로 중 가장 긴 것(커널이 그 대역으로 보낼 NIC) + 항목 안쪽의 경로(항목이 NIC 서브넷보다 넓을 때)
    local net=$1 fam=$2
    {
        ip -"$fam" -o route show match "$net" 2>/dev/null | awk -v fam="$fam" "$HW_ROUTE_AWK" \
            | awk '{ if ($1 > best) { best = $1; n = 0 } if ($1 == best) d[++n] = $2 } END { for (i = 1; i <= n; i++) print d[i] }'
        ip -"$fam" -o route show root "$net" 2>/dev/null | awk -v fam="$fam" "$HW_ROUTE_AWK" | awk '{ print $2 }'
    } | LC_ALL=C sort -u
    return 0
}

default_route_devs() {   # $1=4|6 -> 기본 경로의 인터페이스 (보통 현장 LAN/WAN 쪽 NIC)
    ip -"$1" -o route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }' | LC_ALL=C sort -u
    return 0
}

ip_words() {   # $1=IPv4/IPv6 주소 $2=4|6 -> 16비트 단어(10진, 공백 구분: v4 2개 / v6 8개). 형식이 틀리면 실패
    local s=$1 head tail i
    local -a h=() t=() w=()
    if [[ $2 == 4 ]]; then
        [[ $s =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
        printf '%d %d' $(( (10#${BASH_REMATCH[1]} << 8) | 10#${BASH_REMATCH[2]} )) $(( (10#${BASH_REMATCH[3]} << 8) | 10#${BASH_REMATCH[4]} ))
        return 0
    fi
    if [[ $s =~ ^(.*:)([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then   # 끝의 IPv4 표기 (::ffff:a.b.c.d)
        s=${BASH_REMATCH[1]}$(printf '%x:%x' $(( (10#${BASH_REMATCH[2]} << 8) | 10#${BASH_REMATCH[3]} )) $(( (10#${BASH_REMATCH[4]} << 8) | 10#${BASH_REMATCH[5]} )))
    fi
    [[ $s =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    if [[ $s == *::* ]]; then
        head=${s%%::*} tail=${s#*::}
        [[ $tail != *::* ]] || return 1
        [[ -z $head ]] || IFS=: read -r -a h <<< "$head"
        [[ -z $tail ]] || IFS=: read -r -a t <<< "$tail"
        (( ${#h[@]} + ${#t[@]} < 8 )) || return 1
        w=("${h[@]}")
        for (( i = ${#h[@]} + ${#t[@]}; i < 8; i++ )); do w+=(0); done
        w+=("${t[@]}")
    else
        IFS=: read -r -a w <<< "$s"
    fi
    (( ${#w[@]} == 8 )) || return 1
    for i in "${!w[@]}"; do
        [[ ${w[i]} =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        w[i]=$(( 16#${w[i]} ))
    done
    printf '%s' "${w[*]}"
}

cidr_overlap() {   # $1 $2 = 주소[/길이] $3=4|6 -> 두 대역이 겹치면 참 (짧은 쪽 길이까지 비트가 같음)
    local max p q n i k x y
    local -a A=() B=()
    max=$([[ $3 == 4 ]] && echo 32 || echo 128)
    p=$max q=$max
    [[ $1 != */* ]] || p=${1#*/}
    [[ $2 != */* ]] || q=${2#*/}
    [[ $p =~ ^[0-9]{1,3}$ && $q =~ ^[0-9]{1,3}$ ]] && (( 10#$p <= max && 10#$q <= max )) || return 1
    n=$(( 10#$p < 10#$q ? 10#$p : 10#$q ))
    x=$(ip_words "${1%%/*}" "$3") && y=$(ip_words "${2%%/*}" "$3") || return 1
    read -r -a A <<< "$x"
    read -r -a B <<< "$y"
    for (( i = 0; n > 0; i++, n -= 16 )); do
        k=$(( n < 16 ? n : 16 ))
        (( (A[i] >> (16 - k)) == (B[i] >> (16 - k)) )) || return 1
    done
    return 0
}

cidr_same() {   # $1 $2 = 주소[/길이] $3=4|6 -> 같은 대역이면 참 (nft 가 호스트 비트를 지워 보여 줘도 같음)
    local max p q
    max=$([[ $3 == 4 ]] && echo 32 || echo 128)
    p=$max q=$max
    [[ $1 != */* ]] || p=${1#*/}
    [[ $2 != */* ]] || q=${2#*/}
    [[ $p =~ ^[0-9]{1,3}$ && $q =~ ^[0-9]{1,3}$ ]] && (( 10#$p == 10#$q )) && cidr_overlap "$1" "$2" "$3"
}

nic_addrs() {   # $1=인터페이스 $2=4|6 [$3=global: scope global 만] -> 그 NIC 의 주소/길이 (점대점이면 상대 접두사도). 한 줄에 하나
    ip -"$2" -o addr show dev "$1" ${3:+scope global} 2>/dev/null \
        | awk -v max="$([[ $2 == 4 ]] && echo 32 || echo 128)" '
            { for (i = 1; i < NF; i++) if ($i == "inet" || $i == "inet6") {
                  print ($(i + 1) ~ /\// ? $(i + 1) : $(i + 1) "/" max)
                  if ($(i + 2) == "peer") print $(i + 3)
                  break } }'
    return 0
}

nic_overlaps() {   # $1=인터페이스 $2=대역 $3=4|6 -> 그 NIC 의 주소 중 하나라도 대역과 겹치면 참
    local a
    while IFS= read -r a; do
        [[ -n $a ]] && cidr_overlap "$a" "$2" "$3" && return 0
    done < <(nic_addrs "$1" "$3")
    return 1
}

nic_other_addr() {   # $1=인터페이스 $2=대역 $3=4|6 -> 대역과 겹치지 않는 scope global 주소가 있으면 첫 번째를 출력 (참)
    local a
    while IFS= read -r a; do
        [[ -n $a ]] || continue
        cidr_overlap "$a" "$2" "$3" || { printf '%s' "$a"; return 0; }
    done < <(nic_addrs "$1" "$3" global)
    return 1
}

hw_bind_devs() {   # $1=HW_NETS 항목 $2=4|6 -> 신뢰할 HW NIC: 그 대역의 직접 연결 경로가 있고 NIC 주소가 대역과 겹침
    local d
    while IFS= read -r d; do
        if [[ -n $d ]] && nic_overlaps "$d" "$1" "$2"; then printf '%s\n' "$d"; fi
    done < <(hw_net_devs "$1" "$2")
    return 0
}

hw_rule_binds() {   # stdin = 렌더 결과 또는 nft list 출력 -> HW_NETS iifname 규칙마다 "ip|ip6 대역 NIC..." 한 줄
    awk 'index($0, "comment \"robot hardware net (HW_NETS") && $1 == "iifname" && $2 != "!=" {
             for (i = 2; i < NF; i++) if ($i == "saddr") break
             s = ""
             for (j = 2; j < i - 1; j++) { n = $j; gsub(/[{},"]/, "", n); if (n != "") s = s " " n }
             print $(i - 1), $(i + 1) s
         }'
    return 0
}

hg_prev_hw_devs() {   # $1=HW_NETS 항목 $2=ip|ip6 -> 지금 적용된 렌더 결과($HG_NFT)에서 그 항목이 묶여 있던 NIC (한 줄에 하나)
    [[ -r $HG_NFT ]] || return 0
    hw_rule_binds < "$HG_NFT" | awk -v kw="$2" -v net="$1" '$1 == kw && $2 == net { for (i = 3; i <= NF; i++) print $i; exit }'
    return 0
}

iif_excl() {   # $1=인터페이스 목록(줄 단위) -> 'iifname != "a" ' / 'iifname != { "a", "b" } ' / '' (렌더할 수 없는 이름은 경고 후 뺌)
    local d
    local -a q=()
    while IFS= read -r d; do
        [[ -n $d ]] || continue
        if [[ $d =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
            q+=("\"$d\"")
        else
            hw_warn "기본 경로 인터페이스 이름 '$d' 은(는) 렌더할 수 없어 HW_NETS 제외 목록에서 뺌"
        fi
    done <<< "$1"
    case ${#q[@]} in
        0) ;;
        1) printf 'iifname != %s ' "${q[0]}" ;;
        *) printf 'iifname != { %s } ' "$(join_list "${q[@]}")" ;;
    esac
}

hw_warn() { [[ -n ${HG_QUIET:-} ]] || echo "[guard] 경고: $*" >&2; }

hg_render() {   # $1=observe|enforce $2=open|lock -> 렌더 결과를 stdout 으로 (설정값이 틀리면 die)
    local mode=$1 nif=$2 tok fam v d a kw defs kept policy tag verdict comment m binds="" def4="" def6=""
    local hw_raw hw_strict hw_match="" tcp_raw udp_raw if_raw
    local -a nets4=() nets6=() tcp=() udp=() ifs=() devs=() quoted=()
    local I='        '   # 체인 본문 들여쓰기
    local defines="" hw_rules="" nif_rules="" extra_rules="" final_rules="" info=""

    [[ $mode == observe || $mode == enforce ]] || die "렌더할 수 없는 MODE '$mode' (observe|enforce)"
    [[ $nif == open || $nif == lock ]] || die "nif 모드 '$nif' (open|lock)"
    [[ -f $HG_TEMPLATE ]] || die "$HG_TEMPLATE 없음"

    hw_raw=$(conf_get HW_NETS "$HG_DEFAULT_HW_NETS")
    hw_strict=$(conf_get HW_NETS_STRICT no)
    case $hw_strict in
        yes) hw_match=" fib saddr . iif oif exists" ;;   # 출발지로 가는 경로의 인터페이스로 들어온 것만 (HW 대역 경로가 있을 때만 위조 차단)
        no)  ;;
        *)   die "host-guard.conf HW_NETS_STRICT: '$hw_strict' (yes|no)" ;;
    esac
    tcp_raw=$(conf_get EXTRA_TCP_PORTS "")
    udp_raw=$(conf_get EXTRA_UDP_PORTS "")
    if_raw=$(conf_get TRUST_IFACES "")

    while IFS= read -r tok; do
        [[ -n $tok ]] || continue
        fam=$(net_family "$tok") || die "host-guard.conf HW_NETS: '$tok' 는 IPv4/IPv6 주소·CIDR 가 아님"
        if [[ $fam == 4 ]]; then nets4+=("$tok"); else nets6+=("$tok"); fi
    done < <(split_list "$hw_raw")
    while IFS= read -r tok; do
        [[ -n $tok ]] || continue
        v=$(norm_port "$tok") || die "host-guard.conf EXTRA_TCP_PORTS: '$tok' (1-65535 또는 a-b)"
        # 51231/51233 은 nif.mode=open 일 때만 열린다 — lock 에서 EXTRA_TCP_PORTS 로 우회해 열지 못하게
        if [[ $nif == lock ]] && { port_in 51231 "$v" || port_in 51233 "$v"; }; then
            die "host-guard.conf EXTRA_TCP_PORTS: '$tok' 가 51231/51233 을 포함 — nif.mode=lock 과 모순 (그 포트는 nif-open 으로만 엶). EXTRA_TCP_PORTS 에서 빼세요"
        fi
        tcp+=("$v")
    done < <(split_list "$tcp_raw")
    while IFS= read -r tok; do
        [[ -n $tok ]] || continue
        v=$(norm_port "$tok") || die "host-guard.conf EXTRA_UDP_PORTS: '$tok' (1-65535 또는 a-b)"
        udp+=("$v")
    done < <(split_list "$udp_raw")
    while IFS= read -r tok; do
        [[ -n $tok ]] || continue
        [[ $tok =~ ^[A-Za-z0-9_.-]{1,15}\*?$ ]] || die "host-guard.conf TRUST_IFACES: '$tok' (인터페이스 이름, 와일드카드는 끝에만)"
        ifs+=("\"$tok\"")
    done < <(split_list "$if_raw")

    info+="# ---- 렌더 결과: $(date '+%F %T %z') install_vizanti_gateway.sh — 직접 고치지 말 것 ----"$'\n'
    info+="# MODE=$mode  nif.mode=$nif"$'\n'
    info+="# HW_NETS=${hw_raw}  HW_NETS_STRICT=${hw_strict}"$'\n'
    info+="# EXTRA_TCP_PORTS=${tcp_raw}  EXTRA_UDP_PORTS=${udp_raw}  TRUST_IFACES=${if_raw}"$'\n'

    def4=$(default_route_devs 4)
    def6=$(default_route_devs 6)
    if [[ $hw_strict == yes ]]; then   # 패킷마다 커널 경로 검사 — HW NIC 가 늦게 올라오거나 이름이 바뀌어도 따라감
        # fib saddr . iif 는 "출발지로 가는 최선 경로의 NIC = 들어온 NIC" 만 본다. HW 대역의 직접 경로가 없으면 기본 경로가 답이 되어
        # 그 NIC(현장 LAN)로 온 위조도 통과하므로 렌더 시점의 기본 경로 NIC 는 이름으로 뺀다 (기본 경로 NIC 가 바뀌면 reload)
        if (( ${#nets4[@]} )); then
            defines+="define HW_NETS = { $(join_list "${nets4[@]}") }"$'\n'
            hw_rules+="${I}$(iif_excl "$def4")ip saddr \$HW_NETS${hw_match} accept comment \"robot hardware nets (HW_NETS, fib)\""$'\n'
        fi
        if (( ${#nets6[@]} )); then
            defines+="define HW_NETS6 = { $(join_list "${nets6[@]}") }"$'\n'
            hw_rules+="${I}$(iif_excl "$def6")ip6 saddr \$HW_NETS6${hw_match} accept comment \"robot hardware nets (HW_NETS IPv6, fib)\""$'\n'
        fi
        for v in "${nets4[@]}" "${nets6[@]}"; do
            fam=$(net_family "$v")
            defs=$([[ $fam == 4 ]] && echo "$def4" || echo "$def6")
            devs=()
            while IFS= read -r d; do [[ -z $d ]] || devs+=("$d"); done < <(hw_bind_devs "$v" "$fam")
            (( ${#devs[@]} )) \
                || hw_warn "HW_NETS '$v': 지금 이 대역 주소를 가진 직접 연결 NIC 가 없음 — HW NIC 로 오는 이 출발지 패킷은 $([[ $mode == enforce ]] && echo '막히고' || echo 'rgt-guard 로 기록되고(enforce 면 막힘)'), 이 출발지로 가는 다른 경로(VPN 등)의 NIC 로 들어온 위조는 통과 (기본 경로 NIC 는 렌더 시점 기준으로 제외). 로봇에 없는 대역이면 HW_NETS 에서 뺄 것"
            [[ $mode == enforce ]] || continue
            for d in "${devs[@]}"; do   # 사이트망과 같은 대역: 기본 경로 NIC 로 온 것은 위 제외로 신뢰하지 않음
                grep -qxF -- "$d" <<< "$defs" || continue
                hw_warn "HW_NETS '$v' 가 기본 경로 NIC '$d'(현장 LAN 쪽)와 겹침 — 그 NIC 로 들어온 이 대역은 신뢰하지 않으며, 경로 우선순위에 따라 HW NIC 의 정상 패킷도 막힐 수 있음. 그 대역을 HW_NETS 에서 빼고 HW NIC 이름을 TRUST_IFACES 에"
            done
        done
    else   # 대역마다 렌더 시점의 HW NIC 에 고정: loose rp_filter(Ubuntu 기본 2)는 다른 NIC 로 들어온 위조 출발지를 버리지 않음
        for v in "${nets4[@]}" "${nets6[@]}"; do
            fam=$(net_family "$v")
            kw=$([[ $fam == 4 ]] && echo ip || echo ip6)
            defs=$([[ $fam == 4 ]] && echo "$def4" || echo "$def6")
            devs=()
            quoted=()
            kept=""
            while IFS= read -r d; do   # 이름은 렌더 결과에 따옴표로 들어가므로 TRUST_IFACES 와 같은 문자만
                [[ -n $d ]] || continue
                if [[ ! $d =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
                    hw_warn "HW_NETS '$v': 인터페이스 이름 '$d' 은(는) 렌더할 수 없어 제외"
                elif ! nic_overlaps "$d" "$v" "$fam"; then   # 경로만 있고 대역 주소가 없음: VPN(wg-quick 10.0.0.0/8 dev wg0)·수동 LAN 경로
                    hw_warn "HW_NETS '$v': '$d' 에 이 대역 경로가 있지만 NIC 주소가 대역과 겹치지 않음 (VPN·LAN 쪽 경로) — 그 NIC 는 신뢰하지 않음"
                else
                    devs+=("$d")
                fi
            done < <(hw_net_devs "$v" "$fam")
            if (( ! ${#devs[@]} )); then   # 렌더 순간 링크가 내려가 주소가 빠졌어도, 지금 적용된 바인딩은 버리지 않음
                while IFS= read -r d; do
                    [[ $d =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || continue
                    if grep -qxF -- "$d" <<< "$defs"; then
                        hw_warn "HW_NETS '$v': 이전 렌더의 NIC '$d' 은(는) 지금 기본 경로 NIC 라 유지하지 않음"
                    elif a=$(nic_other_addr "$d" "$v" "$fam"); then
                        hw_warn "HW_NETS '$v': 이전 렌더의 NIC '$d' 에 지금 다른 대역 주소($a)가 있어 유지하지 않음"
                    else
                        devs+=("$d")
                    fi
                done < <(hg_prev_hw_devs "$v" "$kw")
                (( ! ${#devs[@]} )) || kept=1
            fi
            if (( ! ${#devs[@]} )); then
                binds+="  $v -> 없음(신뢰 안 함)"
                hw_rules+="${I}# HW_NETS $v: 직접 연결된 NIC 없음 (렌더 시점) — 신뢰하지 않음"$'\n'
                hw_warn "HW_NETS '$v': 로봇에 이 대역의 직접 연결 경로(NIC)가 없어 신뢰하지 않음 — $([[ $mode == enforce ]] && echo 'enforce 에서 이 출발지 패킷은 막힘' || echo 'observe 는 rgt-guard 로 기록만 (enforce 면 막힘)'). NIC·주소를 확인한 뒤 host-guard reload"
                continue
            fi
            for d in "${devs[@]}"; do quoted+=("\"$d\""); done
            m=${quoted[0]}
            (( ${#quoted[@]} == 1 )) || m="{ $(join_list "${quoted[@]}") }"
            if [[ -n $kept ]]; then
                binds+="  $v -> $(join_list "${devs[@]}")(이전 렌더 유지)"
                hw_rules+="${I}iifname $m $kw saddr $v accept comment \"robot hardware net (HW_NETS, kept)\""$'\n'
                hw_warn "HW_NETS '$v': 지금 이 대역 주소를 가진 직접 연결 NIC 가 없어 이전 렌더의 바인딩($(join_list "${devs[@]}"))을 유지 — 링크·주소가 돌아오면 그대로 동작. NIC 를 바꾼 것이면 연결 후 host-guard reload"
            else
                binds+="  $v -> $(join_list "${devs[@]}")"
                hw_rules+="${I}iifname $m $kw saddr $v accept comment \"robot hardware net (HW_NETS)\""$'\n'
            fi
            [[ $mode == enforce ]] || continue
            for d in "${devs[@]}"; do   # 기본 경로 NIC 에 이 대역 주소 = 현장 LAN 과 겹침: 그 LAN 의 호스트가 이 대역 주소로 위조하면 통과
                grep -qxF -- "$d" <<< "$defs" || continue
                hw_warn "HW_NETS '$v' 가 기본 경로 NIC '$d'(현장 LAN 쪽)에 묶임 — 그 LAN 의 호스트가 출발지를 이 대역으로 위조하면 enforce 를 우회함. LAN 대역을 포함하지 않게 HW_NETS 를 고치고, 사이트망이 같은 대역이면 그 대역을 HW_NETS 에서 빼고 HW NIC 이름을 TRUST_IFACES 에 (범위 좁히기·HW_NETS_STRICT=yes 로는 막히지 않음)"
            done
        done
        if (( ${#nets4[@]} + ${#nets6[@]} )); then
            defines="# (HW_NETS_STRICT=no: 대역별 iifname 규칙 — define 없음)"$'\n'
            info+="# HW_NETS 인터페이스 (렌더 시점 직접 연결 경로):${binds}"$'\n'
        fi
    fi
    [[ -n $defines ]] || defines="# (HW_NETS 비어 있음 — define 없음)"$'\n'
    [[ -n $hw_rules ]] || hw_rules="${I}# (HW_NETS 비어 있음 — 하드웨어망 예외 없음)"$'\n'

    if [[ $nif == open ]]; then
        # 조사용 기록: 새 출발지(:포트)마다 10분에 1줄. 기록 규칙은 판정을 내리지 않고, 다음 줄이 무조건 accept.
        # 전용 세트(seen_nif4/6): 다른 포트 스캔이 seen4/6 을 채워도 51231/51233 호출자 기록은 빠지지 않음
        nif_rules+="${I}tcp dport { 51231, 51233 } ip saddr . tcp dport != @seen_nif4 limit rate 20/second burst 50 packets add @seen_nif4 { ip saddr . tcp dport } log prefix \"rgt-nif \" level info"$'\n'
        nif_rules+="${I}tcp dport { 51231, 51233 } ip6 saddr . tcp dport != @seen_nif6 limit rate 20/second burst 50 packets add @seen_nif6 { ip6 saddr . tcp dport } log prefix \"rgt-nif \" level info"$'\n'
        nif_rules+="${I}tcp dport { 51231, 51233 } accept comment \"network-iface (nif.mode=open)\""$'\n'
    else
        nif_rules+="${I}# nif.mode=lock: 허용하지 않음 — network-iface 도 127.0.0.1 에만 바인드, LAN 호출은 :5000 /api 경유"$'\n'
    fi

    (( ${#tcp[@]} )) && extra_rules+="${I}tcp dport { $(join_list "${tcp[@]}") } accept comment \"host-guard.conf EXTRA_TCP_PORTS\""$'\n'
    (( ${#udp[@]} )) && extra_rules+="${I}udp dport { $(join_list "${udp[@]}") } accept comment \"host-guard.conf EXTRA_UDP_PORTS\""$'\n'
    (( ${#ifs[@]} )) && extra_rules+="${I}iifname { $(join_list "${ifs[@]}") } accept comment \"host-guard.conf TRUST_IFACES\""$'\n'
    [[ -n $extra_rules ]] || extra_rules="${I}# (없음)"$'\n'

    if [[ $mode == observe ]]; then
        policy=accept tag="rgt-guard " verdict=accept comment="observe: would be dropped under enforce"
    else
        policy=drop tag="rgt-guard-drop " verdict=drop comment="enforce: default deny"
    fi
    # 출발지별 예산(glog_src4/6)이 전역 limit 보다 앞: 한 스캐너가 전역 토큰과 seen4/6 을 독차지하지 못함.
    # 새 출발지의 glog_src4/6 삽입은 바로 앞 규칙이 초당 20개(순간 100)로 제한 — 위조 출발지 순간 플러드로 세트(8192)를 채워
    # 10분간 기록을 끊지 못하게. 상한을 넘은 새 출발지는 기록 없이 최종 판정과 같은 판정 (부정 lookup 은 원소 limit 을 쓰지 않음)
    final_rules+="${I}meta l4proto { tcp, udp } ip saddr . meta l4proto . th dport != @seen4 ip saddr != @glog_src4 limit rate over 20/second burst 100 packets counter $verdict comment \"new-source log cap\""$'\n'
    final_rules+="${I}meta l4proto { tcp, udp } ip saddr . meta l4proto . th dport != @seen4 add @glog_src4 { ip saddr limit rate 1/second burst 20 packets } limit rate 20/second burst 100 packets add @seen4 { ip saddr . meta l4proto . th dport } log prefix \"$tag\" level info"$'\n'
    final_rules+="${I}meta l4proto { tcp, udp } ip6 saddr . meta l4proto . th dport != @seen6 ip6 saddr != @glog_src6 limit rate over 20/second burst 100 packets counter $verdict comment \"new-source log cap\""$'\n'
    final_rules+="${I}meta l4proto { tcp, udp } ip6 saddr . meta l4proto . th dport != @seen6 add @glog_src6 { ip6 saddr limit rate 1/second burst 20 packets } limit rate 20/second burst 100 packets add @seen6 { ip6 saddr . meta l4proto . th dport } log prefix \"$tag\" level info"$'\n'
    final_rules+="${I}meta l4proto != { tcp, udp } limit rate 1/second burst 5 packets log prefix \"$tag\" level info"$'\n'
    final_rules+="${I}counter $verdict comment \"$comment\""$'\n'

    # 자리표시자 치환: 값은 환경변수로 전달 (awk -v 의 역슬래시 해석 회피). 줄 전체 자리표시자 + 인라인 @POLICY@
    HG_RENDER_INFO=$info HG_DEFINES=$defines HG_HW_NET_RULES=$hw_rules HG_NIF_RULES=$nif_rules \
    HG_EXTRA_RULES=$extra_rules HG_FINAL_RULES=$final_rules HG_POLICY=$policy \
    awk '
        /^[ \t]*@[A-Z_]+@[ \t]*$/ {
            name = $0
            gsub(/[ \t@]/, "", name)
            if (!(("HG_" name) in ENVIRON)) { printf "unknown placeholder @%s@\n", name > "/dev/stderr"; bad = 1; next }
            printf "%s", ENVIRON["HG_" name]
            next
        }
        { gsub(/@POLICY@/, ENVIRON["HG_POLICY"]); print }
        END { exit bad }
    ' "$HG_TEMPLATE"
}

hg_render_checked() {   # $1 mode $2 nif $3 출력 파일 — 렌더 + 잔여 자리표시자 검사 (nft 검사는 호출자)
    local out
    out=$(hg_render "$1" "$2") || die "렌더 실패"
    if grep -qE '@[A-Z_]+@' <<< "$out"; then
        die "렌더 결과에 치환되지 않은 자리표시자가 남음: $(grep -oE '@[A-Z_]+@' <<< "$out" | sort -u | tr '\n' ' ')"
    fi
    printf '%s\n' "$out" > "$3"
}

# ================================================================ host guard: 적용·해제·조회
hg_unlisted_tcp_listeners() {   # $1=nif 모드. LAN(비루프백)에 리슨 중이지만 허용 목록 밖인 TCP 포트 = enforce 에서 새 연결이 막힘
    local nif=$1 tok v p out=""
    local -a allow=(22 5000 5001-5003)   # 5001-5003 은 어차피 외부 차단 대상 (경고에서 제외)
    [[ $nif == open ]] && allow+=(51231 51233)
    while IFS= read -r tok; do
        [[ -n $tok ]] || continue
        v=$(norm_port "$tok") && allow+=("$v")
    done < <(split_list "$(conf_get EXTRA_TCP_PORTS "")")
    # ss -H 출력의 4번째 열 = 로컬 주소:포트 (0.0.0.0:22, [::]:22, *:5000, 127.0.0.53%lo:53 ...)
    while IFS= read -r p; do
        [[ $p =~ ^[0-9]+$ ]] || continue
        port_in "$p" "${allow[@]}" || out+="$p "
    done < <(ss -Hltn 2>/dev/null | awk '{ a = $4; p = a; sub(/.*:/, "", p); h = a; sub(/:[^:]*$/, "", h)
                                          if (h ~ /^127\./ || h == "[::1]" || h ~ /%lo$/) next
                                          print p }' | sort -un)
    printf '%s' "${out% }"
}

hg_disable() {
    systemctl disable --now "$HG_UNIT" >/dev/null 2>&1 || true
    nft delete table inet rgt_host_guard 2>/dev/null || true
    echo "[guard] host guard 해제 (table inet rgt_host_guard 삭제, $HG_UNIT 비활성)"
}

hg_apply() {   # 현재 설정(conf MODE + nif.mode)으로 렌더 -> nft -c 검증 -> 유닛 설치 -> 교체·적용 -> 확인
    local mode nif tmp policy prev=""
    mode=$(hg_mode) || exit 1
    nif=$(nif_mode)
    if [[ $mode == off ]]; then
        hg_disable
        return 0
    fi
    tmp=$(mktemp "$VZ_ETC/.firewall-host.nft.XXXXXX") || die "임시 파일 생성 실패"
    if ! ( hg_render_checked "$mode" "$nif" "$tmp" ); then
        rm -f "$tmp"
        die "host guard 렌더 실패 — 기존 룰 유지 ($HG_CONF 확인)"
    fi
    if ! nft -c -f "$tmp"; then
        rm -f "$tmp"
        die "렌더 결과가 nft 검사를 통과하지 못함 — 기존 룰 유지 ($HG_CONF 확인)"
    fi
    chmod 644 "$tmp"
    install -m 644 "$SHARE_DIR/$HG_UNIT" "$HG_UNIT_DST" || { rm -f "$tmp"; die "$HG_UNIT_DST 설치 실패"; }
    ( verify_unit "$HG_UNIT_DST" ) || { rm -f "$tmp"; exit 1; }
    systemctl daemon-reload || { rm -f "$tmp"; die "systemctl daemon-reload 실패"; }
    systemctl enable "$HG_UNIT" >/dev/null 2>&1 || { rm -f "$tmp"; die "$HG_UNIT enable 실패"; }
    # 교체 직전 이전 렌더 결과를 보관 -> 적용이 실패하면 되돌림: 부팅 때 적용될 파일 = 지금 커널에 걸린 룰
    if [[ -f $HG_NFT ]]; then
        prev=$VZ_ETC/.firewall-host.nft.prev
        cp -p "$HG_NFT" "$prev"
    fi
    mv -f "$tmp" "$HG_NFT"
    # oneshot+RemainAfterExit: 이미 active 면 ExecReload(nft -f), 아니면 start
    if ! systemctl reload-or-restart "$HG_UNIT"; then
        if [[ -n $prev ]]; then
            mv -f "$prev" "$HG_NFT"
        else    # 첫 적용 실패: 부팅 때 반쯤 된 상태로 뜨지 않게 유닛도 내림
            rm -f "$HG_NFT"
            systemctl disable "$HG_UNIT" >/dev/null 2>&1 || true
        fi
        die "$HG_UNIT 적용 실패 — 이전 렌더 결과로 되돌림 (journalctl -u $HG_UNIT)"
    fi
    [[ -z $prev ]] || rm -f "$prev"
    policy=accept
    [[ $mode == enforce ]] && policy=drop
    # 출력을 먼저 받아 둠 ("nft ... | grep -q" 는 nft 가 SIGPIPE 를 받아 pipefail 로 실패할 수 있음)
    grep -q "policy $policy;" <<< "$(nft list chain inet rgt_host_guard input 2>/dev/null || true)" \
        || die "table inet rgt_host_guard 이 기대한 상태(policy $policy)로 적용되지 않음"
    echo "[guard] host guard $mode 적용 (nif.mode=$nif — 22/5000 허용$([[ $nif == open ]] && echo ', 51231/51233 허용'); $HG_NFT)"
}

kernel_hw_devs() {   # $1=nft list 출력 $2=HW_NETS 항목 $3=4|6 -> 커널 룰에서 그 대역을 묶은 NIC (쉼표, 정렬). 규칙 없으면 빈 값
    local k n rest kw
    kw=$([[ $3 == 4 ]] && echo ip || echo ip6)
    while read -r k n rest; do
        if [[ $k == "$kw" ]] && cidr_same "$n" "$2" "$3"; then
            tr ' ' '\n' <<< "$rest" | LC_ALL=C sort | paste -sd, -
            return 0
        fi
    done < <(hw_rule_binds <<< "$1")
    return 0
}

kernel_fib_excl() {   # $1=nft list 출력 $2=4|6 -> STRICT=yes 규칙이 있으면 "fib:<제외 NIC 쉼표>" (규칙이 없으면 빈 값)
    awk -v kw="$([[ $2 == 4 ]] && echo ip || echo ip6)" '
        index($0, "comment \"robot hardware nets (HW_NETS") {
            for (i = 1; i < NF; i++) if ($i == "saddr") break
            if ($(i - 1) != kw) next
            s = ""
            if ($1 == "iifname" && $2 == "!=")
                for (j = 3; j < i - 1; j++) { n = $j; gsub(/[{},"]/, "", n); if (n != "") s = s (s == "" ? "" : ",") n }
            print "fib:" s
            exit
        }' <<< "$1"
}

hg_status() {
    local mode nif strict v fam d k now="" krules hwwarn="" excl
    mode=$(hg_mode)
    nif=$(nif_mode)
    strict=$(conf_get HW_NETS_STRICT no)
    echo "설정 파일   : $HG_CONF$([[ -f $HG_CONF ]] || echo ' (없음 — 기본값)')"
    echo "MODE        : $mode"
    echo "nif.mode    : $nif ($NIF_MODE_FILE$([[ -f $NIF_MODE_FILE ]] || echo ' 없음'))"
    echo "HW_NETS     : $(conf_get HW_NETS "$HG_DEFAULT_HW_NETS")   (HW_NETS_STRICT=$strict)"
    krules=$(nft list chain inet rgt_host_guard input 2>/dev/null || true)
    # 커널 룰(렌더 시점 값)과 지금 경로·주소를 대역별로 비교 — 다르면 경고 (부팅은 렌더 없이 같은 파일을 적용)
    while IFS= read -r v; do
        [[ -n $v ]] || continue
        fam=$(net_family "$v") || continue
        d=$(hw_bind_devs "$v" "$fam" | LC_ALL=C sort -u | paste -sd, -)
        now+="  $v -> ${d:-없음}"
        if [[ $strict == yes ]]; then
            [[ -n $d ]] || hwwarn+="경고: HW_NETS $v — 지금 이 대역 주소를 가진 직접 연결 NIC 없음: HW NIC 로 오는 패킷은 enforce 에서 막히고, 이 출발지로 가는 다른 경로(VPN 등)의 NIC 로 온 위조는 통과"$'\n'
            continue
        fi
        [[ -n $krules ]] || continue
        k=$(kernel_hw_devs "$krules" "$v" "$fam")
        [[ $k != "$d" ]] || continue
        if [[ -z $k ]]; then
            hwwarn+="경고: HW_NETS $v — 커널 룰에 iifname 바인딩 없음 (렌더 때 NIC 가 없었음), 지금은 $d → host-guard reload"$'\n'
        elif [[ -z $d ]]; then
            hwwarn+="경고: HW_NETS $v — 커널 룰은 iifname $k, 지금 이 대역 주소를 가진 직접 연결 NIC 없음 (링크 다운·주소 없음? 돌아오면 그대로 동작)"$'\n'
        else
            hwwarn+="경고: HW_NETS $v — 커널 룰은 iifname $k, 지금은 $d (NIC 이름·주소가 바뀜) → host-guard reload"$'\n'
        fi
    done < <(split_list "$(conf_get HW_NETS "$HG_DEFAULT_HW_NETS")")
    echo "HW NIC(지금):${now:-  -}"
    if [[ $strict == yes && -n $krules ]]; then   # 렌더 시점 기본 경로 NIC 제외 목록이 지금 기본 경로와 같은가
        for fam in 4 6; do
            excl=$(kernel_fib_excl "$krules" "$fam")
            [[ -n $excl ]] || continue
            k=$(tr , '\n' <<< "${excl#fib:}" | LC_ALL=C sort | paste -sd, -)
            d=$(default_route_devs "$fam" | paste -sd, -)
            [[ $k == "$d" ]] \
                || hwwarn+="경고: IPv$fam 기본 경로 NIC 가 렌더 때(${k:-없음})와 다름 (지금 ${d:-없음}) — 지금 기본 경로 NIC 로 온 HW 출발지 위조가 제외되지 않음 → host-guard reload"$'\n'
        done
    fi
    [[ -z $hwwarn ]] || printf '%s' "$hwwarn"
    echo "EXTRA_TCP   : $(conf_get EXTRA_TCP_PORTS "")   EXTRA_UDP: $(conf_get EXTRA_UDP_PORTS "")   TRUST_IFACES: $(conf_get TRUST_IFACES "")"
    echo "유닛        : $(systemctl is-enabled "$HG_UNIT" 2>/dev/null || true) / $(systemctl is-active "$HG_UNIT" 2>/dev/null || true)"
    if nft list table inet rgt_host_guard >/dev/null 2>&1; then
        echo "커널 룰     :"
        nft list chain inet rgt_host_guard input | grep -E 'policy|counter|51231|HW_NETS' | sed 's/^[[:space:]]*/    /' || true
    else
        echo "커널 룰     : table inet rgt_host_guard 없음 (적용 안 됨)"
    fi
    local unl
    unl=$(hg_unlisted_tcp_listeners "$nif")
    echo "허용 목록 밖 LAN TCP 리슨: ${unl:-없음}   (enforce 에서 새 연결이 막힘 — 정당하면 EXTRA_TCP_PORTS)"
    echo "조사        : sudo bash $0 host-guard survey   (rgt-nif / rgt-guard 로그 집계)"
}

hg_survey() {   # $1 = journalctl --since (기본 7일). 같은 출발지·프로토콜·포트는 10분에 최대 1줄 -> count ≈ 활동한 10분 구간 수
    local since=${1:-7 days ago} cov first_us nrec nboot rfirst_us nrgt since_s now_s win gap gaps a b act tbl nif
    # -k(--dmesg)는 -b(현재 부팅만)를 함의하므로 쓰지 않음: _TRANSPORT=kernel = 저널에 남은 이전 부팅까지
    echo "[survey] 커널 로그 rgt-nif / rgt-guard / rgt-guard-drop 집계 — 요청 구간: since \"$since\""
    cov=$(journalctl _TRANSPORT=kernel --no-pager -q -o export --output-fields=_BOOT_ID,MESSAGE --since "$since" 2>/dev/null \
          | awk -F= '$1 == "__REALTIME_TIMESTAMP" { n++; ts = $2; if (min == "" || ts + 0 < min + 0) min = ts }
                     $1 == "_BOOT_ID" { boot[$2] = 1 }
                     $1 == "MESSAGE" && $0 ~ /^MESSAGE=rgt-(nif|guard|guard-drop) / { r++; if (rmin == "" || ts + 0 < rmin + 0) rmin = ts }
                     END { k = 0; for (b in boot) k++
                           printf "%s %d %d %s %d", (min == "" ? "-" : min), n, k, (rmin == "" ? "-" : rmin), r }' || true)
    read -r first_us nrec nboot rfirst_us nrgt <<< "${cov:-- 0 0 - 0}"
    now_s=$(date +%s)
    since_s=$(date -d "$since" +%s 2>/dev/null) || since_s=""
    if [[ $first_us != [0-9]* ]]; then
        echo "[survey] 경고: 이 구간에 커널 기록이 없음 (since 형식·저널 확인: journalctl _TRANSPORT=kernel --since \"$since\")" >&2
    else
        echo "[survey] 실제 집계 범위: 가장 이른 커널 기록 $(date -d "@$((first_us / 1000000))" '+%F %T %z') ~ 지금, 부팅 ${nboot}회, ${nrec}줄"
        # 늦은 시작 판정 기준: 야간 전원 끔 정도는 경고하지 않도록 구간의 1/10 과 1시간 중 큰 값
        win=$(( now_s - ${since_s:-$(( first_us / 1000000 ))} ))
        if [[ -n $since_s ]]; then   # 저널이 since 보다 한참 늦게 시작 = 그 앞은 기록 자체가 없음
            gap=$(( first_us / 1000000 - since_s ))
            if (( gap > 3600 && gap * 10 > win )); then
                echo "[survey] 경고: 저널이 요청 구간보다 약 $(( gap / 3600 ))시간 늦게 시작 — 그 전 기간은 집계되지 않음 (휘발성 저널·회전·전원 꺼짐)" >&2
            fi
        fi
        # rgt-* 는 host guard 테이블만 남김: 첫 기록이 커널 기록보다 한참 늦으면 그 앞은 설치 전이거나 꺼져 있었을 수 있음
        if [[ $rfirst_us == [0-9]* ]]; then
            echo "[survey] host guard 기록(rgt-*): 첫 기록 $(date -d "@$((rfirst_us / 1000000))" '+%F %T %z'), ${nrgt}줄"
            gap=$(( (rfirst_us - first_us) / 1000000 ))
            if (( gap > 3600 && gap * 10 > win )); then
                echo "[survey] 경고: 첫 rgt-* 기록이 가장 이른 커널 기록보다 약 $(( gap / 3600 ))시간 늦음 — 그 전에는 host guard 가 기록하지 않았을 수 있음 (설치 전 / host-guard off / 테이블 삭제). 그 기간의 빈 칸은 '호출자 없음'이 아님" >&2
            fi
        else
            echo "[survey] host guard 기록(rgt-*): 없음"
        fi
    fi
    # 구간 중 유닛 정지·적용 실패 ~ 다음 적용 = 기록 없음. host-guard off·uninstall(disable --now)은 남지만
    # 수동 nft delete table·nftables.service flush 는 유닛 로그에 남지 않음 (그때는 위 첫 rgt-* 기록만 단서)
    gaps=$(journalctl -u "$HG_UNIT" --since "$since" --no-pager -q -o short-unix 2>/dev/null \
           | awk '/ systemd\[1\]: (Stopped|Failed to start) / { if (s == "") s = int($1); next }
                  / systemd\[1\]: (Started|Finished|Reloaded) / { if (s != "") { if (int($1) - s >= 60) print s, int($1); s = "" } }
                  END { if (s != "") print s, "-" }' || true)
    if [[ -n $gaps ]]; then
        echo "[survey] 경고: 구간 중 host guard 유닛이 정지·적용 실패한 기간 $(grep -c . <<< "$gaps")개 — 그동안은 기록이 없으므로 빈 칸은 '호출자 없음'이 아님:" >&2
        while read -r a b; do
            echo "[survey]       $(date -d "@$a" '+%F %T %z') ~ $([[ $b == - ]] && echo 지금 || date -d "@$b" '+%F %T %z')" >&2
        done < <(tail -n 5 <<< "$gaps")
    fi
    [[ -d /var/log/journal ]] || echo "[survey] 참고: /var/log/journal 없음 — 저널이 휘발성이면 재부팅 전 기록은 남지 않음"
    act=$(systemctl is-active "$HG_UNIT" 2>/dev/null || true)
    tbl=없음
    nft list table inet rgt_host_guard >/dev/null 2>&1 && tbl=있음
    nif=$(nif_mode)
    echo "[survey] host guard: 유닛 ${act:-?}, table inet rgt_host_guard $tbl, MODE=$(conf_get MODE observe), nif.mode=$nif"
    if [[ $act != active || $tbl != 있음 ]]; then
        echo "[survey] 경고: host guard 비활성 — 꺼져 있는 동안은 rgt-nif / rgt-guard 기록이 생기지 않으므로 빈 표는 '호출자 없음'이 아님 (켜기: host-guard observe)" >&2
    fi
    if [[ $nif == lock ]]; then
        echo "[survey] 참고: nif.mode=lock — rgt-nif 행은 새로 생기지 않음 (LAN 의 51231/51233 호출 시도는 rgt-guard / rgt-guard-drop 의 dport 행)"
    fi
    echo "[survey] count = 기록된 10분 구간 수 (출발지·프로토콜·목적 포트별 10분에 최대 1줄. 기록 예산·seen 세트가 찬 동안은 빠짐)"
    printf '%6s  %-14s %-10s %-39s %-6s %s\n' count tag iface source proto dport
    journalctl _TRANSPORT=kernel --no-pager -q -o short-iso --since "$since" 2>/dev/null \
        | grep -E ' rgt-(nif|guard|guard-drop) ' \
        | awk '{
            tag = ""; inif = "-"; src = "-"; proto = "-"; dpt = "-"
            for (i = 1; i <= NF; i++) {
                if ($i == "rgt-nif" || $i == "rgt-guard" || $i == "rgt-guard-drop") tag = $i
                else if ($i ~ /^IN=/) inif = substr($i, 4)
                else if ($i ~ /^SRC=/) src = substr($i, 5)
                else if ($i ~ /^PROTO=/) proto = substr($i, 7)
                else if ($i ~ /^DPT=/) dpt = substr($i, 5)
            }
            if (tag == "") next
            key = sprintf("%-14s %-10s %-39s %-6s %s", tag, inif, src, proto, dpt)
            n[key]++; last[key] = $1
          }
          END { for (k in n) printf "%6d  %s   (last %s)\n", n[k], k, last[k] }' \
        | sort -k1,1nr || true
    echo "[survey] rgt-nif = nif open 중 51231/51233 호출자, rgt-guard = observe 에서 enforce 시 막힐 것, rgt-guard-drop = enforce 에서 버린 것"
}

gw_api_ready() {   # 로컬 게이트웨이가 /api 프록시를 제공하는가 (/gw/info "api": 1, v1.3.0+)
    python3 -I - <<'PY' 2>/dev/null
import json, ssl, sys, urllib.request
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
# sudo 환경에 /etc/environment 의 *_proxy 가 들어오면 urlopen 은 127.0.0.1 도 프록시로 보냄 (no_proxy 의 localhost·CIDR 로는 안 빠짐)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
for url in ("https://127.0.0.1:5000/gw/info", "http://127.0.0.1:5000/gw/info"):
    try:
        with opener.open(url, timeout=3) as resp:
            info = json.loads(resp.read(65536).decode("utf-8"))
        sys.exit(0 if info.get("api") == 1 else 2)
    except Exception:   # SystemExit 은 Exception 이 아니므로 위 sys.exit 는 그대로 전달됨
        continue
sys.exit(1)
PY
}

gw_running_version() {   # 지금 127.0.0.1:5000 에서 응답하는 게이트웨이의 /gw/info "version" (gw_api_ready 와 같은 방식). 무응답 -> 실패
    python3 -I - <<'PY' 2>/dev/null
import json, ssl, sys, urllib.request
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))   # 프록시 무시 (gw_api_ready 참조)
for url in ("https://127.0.0.1:5000/gw/info", "http://127.0.0.1:5000/gw/info"):
    try:
        with opener.open(url, timeout=3) as resp:
            v = json.loads(resp.read(65536).decode("utf-8")).get("version")
    except Exception:
        continue
    print(v if isinstance(v, str) else "?")
    sys.exit(0)
sys.exit(1)
PY
}

old_nav_launches() {   # 구버전(3.3.0 까지) rgt_nav3_launch/launch/vizanti.launch.py 사본 목록 (한 줄에 하나)
    # 모든 그룹 오버레이 + test_ws (robot-env.sh 가 마지막에 source -> 있으면 그쪽이 쓰임; merge/isolated 두 배치).
    # 패턴은 따옴표째 찾음: 교체본 docstring 의 설명 문구에 걸리지 않게
    local f
    for f in "$RGT_WS"/*/share/rgt_nav3_launch/launch/vizanti.launch.py \
             "$GW_HOME/test_ws/install/share/rgt_nav3_launch/launch/vizanti.launch.py" \
             "$GW_HOME/test_ws/install/rgt_nav3_launch/share/rgt_nav3_launch/launch/vizanti.launch.py"; do
        [[ -f $f ]] && grep -qE '"address": ""|"0\.0\.0\.0"|default=5000\)' "$f" && printf '%s\n' "$f"
    done
    return 0
}

nif_set() {   # $1 = open|lock, $2 = --force (lock 의 게이트웨이 확인 생략)
    local m=$1 force=${2:-}
    if [[ $m == lock && $force != --force ]] && ! gw_api_ready; then
        die "로컬 게이트웨이(:5000)가 /api 프록시(/gw/info \"api\": 1, v1.3.0+)를 제공하지 않습니다.
      lock 하면 편집기·RCS 등 LAN 호출자가 로봇 API 에 접근할 수 없습니다.
      게이트웨이 상태(systemctl status vizanti-gateway)를 확인하세요. 그래도 잠그려면: nif-lock --force"
    fi
    ensure_vizanti_etc
    local hm=off
    if [[ -f $HG_UNIT_DST ]]; then
        hm=$(hg_mode) || exit 1
    fi
    if [[ $hm != off ]]; then   # 바꾸기 전에 새 nif 모드로 렌더 검사 — 설정이 모순이면(예: lock + EXTRA_TCP_PORTS 51231) 아무것도 바꾸지 않음
        ( HG_QUIET=1 hg_render_checked "$hm" "$m" /dev/null ) \
            || die "host guard 를 nif.mode=$m 로 렌더할 수 없어 nif.mode 를 바꾸지 않았습니다 ($HG_CONF 확인)"
    fi
    local prev_nif
    prev_nif=$(tr -d '[:space:]' < "$NIF_MODE_FILE" 2>/dev/null || true)
    write_nif_mode "$m"
    echo "[nif] $NIF_MODE_FILE = $m"
    if [[ $hm != off ]]; then
        if ! ( hg_apply ); then   # 방화벽이 따라오지 못했으면 nif.mode 도 되돌림 (network-iface 는 아직 재시작 전)
            case $prev_nif in
                open|lock) write_nif_mode "$prev_nif"
                           die "host guard 적용 실패 — $NIF_MODE_FILE 를 '$prev_nif' 로 되돌렸습니다" ;;
                *)         die "host guard 적용 실패 ($NIF_MODE_FILE = $m 유지)" ;;
            esac
        fi
    else
        echo "[guard] host guard 미설치 또는 off — 방화벽 변경 없음"
    fi
    cat <<EOF
[nif] network-iface 는 기동할 때 한 번만 바인드 주소를 정합니다 — network-iface 노드(ROS 스택)를 재시작해야 반영됩니다.
      확인: ss -ltn '( sport = :51231 or sport = :51233 )'   (lock: 127.0.0.1 만 / open: * 또는 [::])
EOF
    ss -Hltn '( sport = :51231 or sport = :51233 )' 2>/dev/null | awk '{print "      현재 리슨: " $4}' || true
    if [[ $m == lock ]]; then
        echo "[nif] 되돌리기(롤백): sudo bash $0 nif-open  후 network-iface 재시작"
    fi
}

# ================================================================ 루트 불필요 명령
case "${1:-}" in
    -h|--help|help)
        usage
        exit 0 ;;
    host-guard)
        if [[ "${2:-}" == render ]]; then   # 미리보기: 현재 설정(또는 인자)으로 렌더해 stdout 출력
            r_mode=${3:-$(hg_mode)}
            [[ $r_mode != off ]] || r_mode=observe
            hg_render_checked "$r_mode" "${4:-$(nif_mode)}" /dev/stdout
            exit 0
        fi ;;
esac

[[ $EUID -eq 0 ]] || { echo "sudo 로 실행하세요" >&2; exit 1; }

# ---------------------------------------------------------------- nif-open / nif-lock
case "${1:-}" in
    nif-open)
        nif_set open
        exit 0 ;;
    nif-lock)
        nif_set lock "${2:-}"
        exit 0 ;;
    host-guard)
        case "${2:-}" in
            observe|enforce|off)
                ensure_vizanti_etc
                if [[ $2 == enforce ]]; then   # 경고만 (막지 않음): 예) sshd 가 22 가 아닌 포트에서 리슨하면 새 SSH 접속이 막힘
                    unlisted=$(hg_unlisted_tcp_listeners "$(nif_mode)")
                    if [[ -n $unlisted ]]; then
                        echo "[guard] 경고: enforce 에서 새 연결이 막힐 LAN TCP 리슨 포트: $unlisted" >&2
                        echo "[guard]       정당한 서비스면 $HG_CONF 의 EXTRA_TCP_PORTS 에 추가 후 host-guard reload (ss -ltnp 로 프로세스 확인)" >&2
                    fi
                fi
                prev_mode=$(conf_get MODE observe)
                conf_set MODE "$2"
                if ! ( hg_apply ); then   # 적용 실패 = 커널·렌더 파일은 이전 그대로 -> 설정 파일도 맞춰 되돌림
                    case $prev_mode in observe|enforce|off) conf_set MODE "$prev_mode" ;; esac
                    die "host guard $2 적용 실패 — $HG_CONF 의 MODE 를 '$prev_mode' 로 되돌렸습니다"
                fi
                if [[ $2 == enforce ]]; then
                    echo "[guard] enforce: 기존 연결은 유지되고 새 연결만 판정됩니다. 문제 시 즉시: sudo bash $0 host-guard observe"
                fi ;;
            reload)
                ensure_vizanti_etc
                hg_apply ;;
            status)
                hg_status ;;
            survey)
                hg_survey "${3:-}" ;;
            *)
                die "사용법: host-guard observe|enforce|off|reload|status|survey [since]|render [mode] [nif]" ;;
        esac
        exit 0 ;;
    ssh-keyonly)
        shift
        exec /bin/bash "$SHARE_DIR/ssh-keyonly.sh" "$@" ;;
esac

# ---------------------------------------------------------------- uninstall
if [[ "${1:-}" == "uninstall" ]]; then
    systemctl disable --now vizanti-gateway.service 2>/dev/null || true
    systemctl disable --now vizanti-firewall.service 2>/dev/null || true
    systemctl disable --now "$HG_UNIT" 2>/dev/null || true
    rm -f "$UNIT_DST" "$FW_UNIT_DST" "$NFT_DST" "$HG_UNIT_DST" "$HG_NFT"
    sed -i '\#include "/etc/vizanti-firewall.nft"#d' /etc/nftables.conf 2>/dev/null || true
    nft delete table inet vizanti_guard 2>/dev/null || true
    nft delete table inet rgt_host_guard 2>/dev/null || true
    if [[ -f "$UFW_MARKER" ]]; then
        ufw delete allow 5000/tcp >/dev/null 2>&1 || true
        rm -f "$UFW_MARKER"
    fi
    systemctl daemon-reload
    cat <<EOF
[uninstall] 게이트웨이·방화벽·host guard 제거 완료. $DATA_DIR (등록/인증서) 와 $VZ_ETC (nif.mode, host-guard.conf) 는 보존됨.
[uninstall] 주의: 이 상태에서는 vizanti 백엔드가 루프백에만 떠 있어 어떤 PC 도 SLAM 화면을 열 수 없습니다(fail-closed).
            완전 롤백 = nav 패키지(rgt_nav3_launch) 를 3.3.0 으로 되돌려 vizanti 를 다시 0.0.0.0 에 띄우는 것 (무인증 노출 복귀).
            긴급 열람 = SSH 터널: ssh -L 5002:127.0.0.1:5002 -L 5000:127.0.0.1:5001 $GW_USER@ROBOT  ->  http://127.0.0.1:5002
[uninstall] nif.mode = $(nif_mode) — lock 이면 게이트웨이(/api) 없이 51231/51233 에 LAN 접근 불가.
            LAN 노출로 되돌리려면: sudo bash $0 nif-open  후 network-iface 재시작
EOF
    exit 0
fi

# ---------------------------------------------------------------- firewall-only (Phase 0)
if [[ "${1:-}" == "firewall-only" ]]; then
    TMP_NFT=$(mktemp)
    trap 'rm -f "$TMP_NFT"' EXIT
    sed '/allow_gateway/d' "$SHARE_DIR/firewall-vizanti.nft" > "$TMP_NFT"   # 5000-5003 전부 외부 차단
    install_firewall "$TMP_NFT" phase0
    rm -f "$TMP_NFT"
    echo "[phase0] 5000-5003 외부 차단 적용 (재부팅 영속). 정식 설치 시 이 룰은 자동 교체됩니다."
    if systemctl is-active --quiet vizanti-gateway.service; then
        echo "[phase0] 주의: vizanti-gateway 가 동작 중이지만 이제 LAN 에서 5000 에 닿지 않습니다 (되돌리기: sudo bash $0)" >&2
    fi
    exit 0
fi

[[ -z "${1:-}" ]] || die "알 수 없는 명령 '$1' (도움말: bash $0 --help)"

# ---------------------------------------------------------------- 정식 설치
[[ -f "$GW_BIN" ]] || { echo "오류: $GW_BIN 없음 — vizanti_server 패키지를 먼저 배포하세요" >&2; exit 1; }
if ! python3 -c 'import cryptography' 2>/dev/null; then
    echo "[dep] python3-cryptography 설치 시도 (오프라인 로봇이면 미리 deb 를 준비하세요)"
    apt-get install -y python3-cryptography || { echo "오류: python3-cryptography 를 설치할 수 없음" >&2; exit 1; }
fi
if ! python3 -c 'from OpenSSL import SSL; assert hasattr(SSL.Connection, "export_keying_material"); assert hasattr(SSL.Context, "set_min_proto_version"); assert SSL.TLS1_3_VERSION' 2>/dev/null; then
    echo "[dep] python3-openssl 설치 시도 (TLS exporter 기반 접속 코드 등록에 필요)"
    apt-get install -y python3-openssl || die "python3-openssl 설치 실패 — 운영 서비스는 변경하지 않았습니다"
fi
python3 -c 'from OpenSSL import SSL; assert hasattr(SSL.Connection, "export_keying_material"); assert hasattr(SSL.Context, "set_min_proto_version"); assert SSL.TLS1_3_VERSION' \
    || die "pyOpenSSL TLS 1.3/exporter API 없음 — 설치를 중단합니다"

# A1: 구버전 nav launch 가 떠 있거나 설치돼 있으면 게이트웨이가 5000 을 열 수 없음 -> 중단
if [[ -n "$(ss -Hltn 'sport = :5000' 2>/dev/null)" ]] && ! systemctl is-active --quiet vizanti-gateway.service; then
    echo "오류: 포트 5000 이 이미 사용 중 — 구버전 vizanti launch(rgt_nav3_launch/vizanti.launch.py, flask 0.0.0.0:5000) 가 떠 있습니다." >&2
    echo "      3.4.0 nav 패키지(rgt_navigation3) 를 먼저 배포하고 nav 스택을 재시작한 뒤 다시 실행하세요." >&2
    ss -ltnp 'sport = :5000' >&2 || true
    exit 1
fi
OLD_NAV=$(old_nav_launches)
if [[ -n $OLD_NAV ]]; then
    echo "오류: 구버전 nav launch(0.0.0.0 / 5000 직접 바인드) 가 설치돼 있습니다 — 3.4.0 nav 패키지가 배포되지 않았습니다:" >&2
    sed 's/^/        /' <<< "$OLD_NAV" >&2
    echo "      deploy/nav3_vizanti.launch.py 내용으로 교체된 rgt_navigation3 를 먼저 배포하세요 (test_ws 의 사본은 지우거나 다시 빌드)." >&2
    exit 1
fi
[[ -f $NAV_LAUNCH ]] || echo "경고: $NAV_LAUNCH 없음 — rgt_nav3_launch 배치를 확인하세요 (bringup 이 vizanti 를 띄우지 못하면 게이트웨이는 502)" >&2

# 1) 데이터 디렉터리 + TLS 인증서 (로봇별 자가서명 — 독립 경로 지문 확인 필수)
install -d -m 700 -o $GW_USER -g $GW_USER "$DATA_DIR"
if [[ ! -f "$DATA_DIR/tls_cert.pem" ]]; then
    ROBOT_UID=$(cat /rgt/robot_uid 2>/dev/null || echo unknown)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$DATA_DIR/tls_key.pem" -out "$DATA_DIR/tls_cert.pem" \
        -days 3650 -nodes -subj "/CN=vizanti-gw-${ROBOT_UID}" 2>/dev/null
    chown $GW_USER:$GW_USER "$DATA_DIR"/tls_*.pem
    chmod 600 "$DATA_DIR"/tls_*.pem
    echo "[tls] 자가서명 인증서 생성 (CN=vizanti-gw-${ROBOT_UID})"
fi

# 2) 방화벽 벨트 (전용 유닛, 재부팅 영속)
# NIF 단일 권위가 현재 TLS 인증서로 실제 응답해야 배포를 계속합니다.
# install_auth.sh가 서비스/RuntimeDirectory를 설치하며 이 스크립트는 중복 소켓을 만들지 않습니다.
[[ -x /usr/local/bin/rgt-nif-auth ]] || die "NIF 인증 서비스 미설치 — network-iface/deploy/install_auth.sh를 먼저 실행하세요"
systemctl enable network-iface-auth.service
systemctl start network-iface-auth.service || die "network-iface-auth.service 시작 실패"
NIF_AUTH_DEADLINE=$((SECONDS + 20))
NIF_AUTH_READY=no
while (( SECONDS < NIF_AUTH_DEADLINE )); do
    if sudo -u "$GW_USER" python3 - "$DATA_DIR/tls_cert.pem" <<'PY'
import hashlib, json, os, socket, ssl, struct, sys
try:
    with open(sys.argv[1]) as stream:
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(stream.read())).hexdigest()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect('/run/rgt-network-iface/gateway.sock')
        uid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        if uid != os.geteuid():
            raise ValueError('unexpected authority UID')
        connection.sendall(b'{"v":1,"op":"info"}\n')
        with connection.makefile('rb') as stream:
            raw = stream.readline(65537)
        if len(raw) > 65536 or not raw.endswith(b'\n'):
            raise ValueError('invalid response')
    reply = json.loads(raw)
    ready = (reply.get('v') == 1 and reply.get('ok') is True
             and reply.get('auth_mode') == 'nif-device-v1'
             and reply.get('cert_fingerprint') == fingerprint)
except Exception:
    ready = False
sys.exit(0 if ready else 1)
PY
    then
        NIF_AUTH_READY=yes
        break
    fi
    sleep 1
done
[[ $NIF_AUTH_READY == yes ]] || die "NIF 인증 서비스가 현재 인증서로 응답하지 않음 — journalctl -u network-iface-auth 확인"
echo "[auth] NIF 단일 권위/인증서 지문 일치 확인"

install_firewall "$SHARE_DIR/firewall-vizanti.nft" gateway
echo "[fw] 5000 허용(연결수/속도 제한), 5001-5003 외부 차단"

# 2b) /etc/vizanti 설정(기존 값 보존) + 호스트 기본 거부 방화벽.
#     첫 설치 = nif lock + enforce. 재설치는 운영자가 고른 MODE/nif 를 유지.
#     host guard 실패 시 설치를 중단하여 차단되지 않은 배포를 성공으로 보고하지 않음
ensure_vizanti_etc
set +e
( set -e; hg_apply )
HG_RC=$?
set -e
if (( HG_RC != 0 )); then
    die "host guard 적용 실패 — 설치 중단. 원인 해결 후: sudo bash $0 host-guard reload"
fi

# 3) 게이트웨이 유닛 — 재설치·업그레이드·롤백도 restart: 이미 떠 있으면 start(enable --now)는 옛 코드를 그대로 둠
#    (첫 설치는 start 와 같음. 세션은 메모리 전용이라 열린 화면은 한 번 끊김)
cp "$SHARE_DIR/vizanti-gateway.service" "$UNIT_DST"
verify_unit "$UNIT_DST"
GW_WANT=$(awk -F'"' '/^VERSION = "/ { print $2; exit }' "$GW_BIN")
[[ -n $GW_WANT ]] || { echo "오류: $GW_BIN 에서 VERSION 을 읽을 수 없음" >&2; exit 1; }
systemctl daemon-reload
systemctl reset-failed vizanti-gateway.service 2>/dev/null || true
systemctl enable vizanti-gateway.service
systemctl restart vizanti-gateway.service \
    || { echo "오류: vizanti-gateway.service 재시작 실패" >&2; journalctl -u vizanti-gateway -n 20 --no-pager >&2 || true; exit 1; }
# restart 는 즉사해도 0 을 반환하므로, 실제로 응답하는 프로세스의 버전 = 설치본 버전인지 확인
GW_GOT=""
GW_DEADLINE=$((SECONDS + 20))
while (( SECONDS < GW_DEADLINE )); do
    sleep 1
    systemctl is-active --quiet vizanti-gateway.service || continue
    GW_GOT=$(gw_running_version) || GW_GOT=""
    [[ $GW_GOT != "$GW_WANT" ]] || break
done
if [[ $GW_GOT != "$GW_WANT" ]]; then
    echo "오류: vizanti-gateway 가 설치본 버전 $GW_WANT 로 응답하지 않음 (https://127.0.0.1:5000/gw/info version: ${GW_GOT:-응답 없음})" >&2
    echo "      5000 을 다른 프로세스가 쥐고 있는지(ss -ltnp 'sport = :5000'), 유닛이 $GW_BIN 을 실행하는지(systemctl cat vizanti-gateway) 확인" >&2
    journalctl -u vizanti-gateway -n 20 --no-pager >&2 || true
    exit 1
fi
echo "[unit] vizanti-gateway.service 기동 (version $GW_GOT)"

# 4) 접속 코드/등록 기기의 유일한 권위는 NIF. legacy clients.json/pairing_code는 사용하지 않음.
echo "[auth] NIF device authority: /run/rgt-network-iface/gateway.sock"
echo "       코드 발급/기기 관리: rgt-nif-auth --help (로봇 GUI는 별도 구현)"
echo "       최초 PC 등록 전 독립 SSH 채널에서 인증서 SHA256 지문을 확인하세요."
openssl x509 -in "$DATA_DIR/tls_cert.pem" -noout -fingerprint -sha256

cat <<EOF

=== 설치 완료 — 검증 ===
  ss -ltnp | grep -E '(0\.0\.0\.0|\[::\]|\*):5000'   # 외부 노출 5000 은 vizanti_gateway.py 뿐이어야 함
  ss -ltn  | grep -E '127\.0\.0\.1:500[12]'          # flask 5002 / rosbridge 5001 은 루프백만 (nav 기동 후)
  curl -ks https://\$(hostname -I | awk '{print \$1}'):5000/   # 401 안내 페이지 (502 면 nav 미기동)
  curl -ks https://127.0.0.1:5000/gw/info             # "version" = $GW_WANT (업그레이드·롤백 후에도 확인)
  nft list table inet vizanti_guard                   # 방화벽 벨트
  journalctl -u vizanti-gateway -f                     # 인증 로그
  sudo bash $0 host-guard status            # host guard (현재 $(hg_mode 2>/dev/null || echo '?')) / nif.mode ($(nif_mode))
  sudo bash $0 host-guard survey            # 51231/51233 호출자·enforce 시 막힐 것 집계 (며칠 관찰 후)
EOF
