#!/bin/bash
# SSH 키 전용 전환 (비밀번호·키보드 대화형 로그인 차단) — 10분 데드맨 자동 원복 포함
#
#   sudo bash ssh-keyonly.sh status            # 유효 설정(sshd -T) 4개 + 데드맨 타이머 상태
#   sudo bash ssh-keyonly.sh apply             # 적용 + 10분 데드맨 무장 (지금 열린 세션은 끊기지 않음)
#   sudo bash ssh-keyonly.sh confirm           # "새 터미널에서 키로 로그인한 세션"에서 10분 안에 실행 -> 영구 확정
#   sudo bash ssh-keyonly.sh confirm --force   # 키 로그인 확인 생략 (콘솔 작업 등 — 권장하지 않음)
#   sudo bash ssh-keyonly.sh revert            # 원복 (비밀번호 로그인 복귀)
#   (install_vizanti_gateway.sh ssh-keyonly <...> 로도 호출 가능)
#
# 설정 (drop-in 10-rgt-keyonly.conf — sshd 는 키마다 "처음 읽은 값"을 쓰고, Ubuntu sshd_config 는 첫 줄의
#       Include /etc/ssh/sshd_config.d/*.conf 를 이름(사전)순으로 읽으므로 sshd_config 본문과 50-cloud-init.conf 보다 우선.
#       10- 보다 앞선 이름(00-, 05- ...)에 반대 값이 있으면 apply 가 sshd -T 로 감지하고 원복한다)
#   PasswordAuthentication no / KbdInteractiveAuthentication no / PermitRootLogin no / PubkeyAuthentication yes
#
# 2단계 구조 — 재부팅에도 잠기지 않게
#   apply   : /etc/ssh/sshd_config.d/10-rgt-keyonly.conf 에는 "Include /run/rgt-ssh-keyonly/pending.conf" 한 줄만 두고
#             실제 설정은 /run(tmpfs) 에 둔다. systemd-run 타이머(10분)가 revert 를 실행한다.
#             transient 타이머는 재부팅하면 사라지지만 /run 도 함께 비므로, confirm 전에 재부팅되면 Include 대상이
#             없어(sshd 는 존재하지 않는 Include 경로를 조용히 무시) 비밀번호 로그인이 자동으로 돌아온다.
#   confirm : 키 로그인 확인(이 세션이 apply 이후에 열린 SSH 세션이거나, apply 이후 공개키 로그인 기록이 있음)
#             -> 타이머 해제 -> 설정을 drop-in 에 직접 기록(영구) -> /run 정리.
#   revert  : drop-in 과 /run 을 지우고 sshd -t 통과 시 reload. 타이머가 부른 revert 는 "확인 대기" 상태일 때만 동작
#             (확정된 설정을 늦게 발동한 타이머가 되돌리지 않음).
#   apply/confirm/revert(타이머 포함)는 /run/rgt-ssh-keyonly.lock 으로 직렬화 — confirm 도중 데드맨이 끼어들지 않음.
#   sshd 반영은 항상 reload(SIGHUP, ExecReload 가 sshd -t 선행) — restart 하지 않음.
#
# 영향: 비밀번호로 SSH 하던 도구(공장 QC 도구, rgt_remote 등 — 공유 비밀번호 평문 내장)는 접속할 수 없게 된다. 키를 먼저 배포할 것.
# 공유 비밀번호는 콘솔 로그인·sudo 에 계속 쓰이므로 confirm 후 반드시 교체할 것 (여러 도구에 퍼져 있음).
#
# 시험용 재정의 (운영에서는 설정하지 말 것): RGT_SSH_ROOT(모든 파일 경로 접두사), RGT_SSH_USER, RGT_SSH_HOME

set -euo pipefail

ROOT=${RGT_SSH_ROOT:-}
SSH_USER=${RGT_SSH_USER:-rgt}
SSHD_DIR=$ROOT/etc/ssh
DROPIN=$SSHD_DIR/sshd_config.d/10-rgt-keyonly.conf
RUN_DIR=$ROOT/run/rgt-ssh-keyonly
PENDING=$RUN_DIR/pending.conf
APPLIED_AT=$RUN_DIR/applied_at
REVERT_COPY=$RUN_DIR/ssh-keyonly.sh     # 타이머가 실행할 사본 (원본 패키지가 그 사이 교체돼도 무관)
LOCK=$ROOT/run/rgt-ssh-keyonly.lock     # apply/confirm/revert(타이머 포함) 직렬화. RUN_DIR 밖 (revert 가 RUN_DIR 를 지움)
TIMER_UNIT=rgt-ssh-keyonly-revert
WINDOW=10min
WINDOW_TEXT="10분"
TAG=rgt-ssh-keyonly
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")

SETTINGS="PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes"

say()  { printf '[ssh-keyonly] %s\n' "$*"; }
warn() { printf '[ssh-keyonly] 경고: %s\n' "$*" >&2; }
die()  { printf '[ssh-keyonly] 오류: %s\n' "$*" >&2; exit 1; }
journal() { logger -t "$TAG" -- "$*" 2>/dev/null || true; }

usage() { sed -n '2,9p' "$SELF" | sed 's/^# \{0,1\}//'; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "'$1' 명령이 없음"; }

take_lock() {   # $1=--from-timer: 데드맨은 접근 복구가 우선 — 잠금을 못 얻어도 경고 후 진행
    exec 9> "$LOCK" || die "잠금 파일 $LOCK 을 열 수 없음"
    if flock -w 120 9; then
        return 0
    fi
    [[ ${1:-} == --from-timer ]] || die "다른 ssh-keyonly 작업이 진행 중입니다 (잠금 $LOCK) — 끝난 뒤 다시 실행하세요"
    warn "잠금을 120초 안에 얻지 못했지만 데드맨 원복을 그대로 진행합니다"
}

user_home() {
    if [[ -n ${RGT_SSH_HOME:-} ]]; then
        printf '%s' "$RGT_SSH_HOME"
    else
        getent passwd "$SSH_USER" | cut -d: -f6
    fi
}

write_file() {   # $1=경로 $2=모드 $3=내용 — 같은 디렉터리 임시 파일 + mv (반쯤 쓰인 설정을 sshd 가 읽지 않게)
    local tmp
    tmp=$(mktemp "$(dirname -- "$1")/.$(basename -- "$1").XXXXXX")
    printf '%s\n' "$3" > "$tmp"
    chmod "$2" "$tmp"
    mv -f -- "$tmp" "$1"
}

dropin_pending() {
    printf '%s\n' "# rgt-ssh-keyonly state=pending  (ssh-keyonly.sh 가 관리 — 직접 고치지 말 것)" \
        "# apply 후 confirm 대기 중. 실제 설정은 아래 /run 파일 — 재부팅하면 사라져 비밀번호 로그인이 자동 복귀." \
        "# ${WINDOW_TEXT} 안에 confirm 하지 않으면 타이머($TIMER_UNIT)가 revert 한다." \
        "Include $PENDING"
}

pending_conf() {
    printf '%s\n' "# rgt-ssh-keyonly: 확인 대기 중인 설정 (tmpfs). confirm 하면 $DROPIN 로 옮겨 영구화" "$SETTINGS"
}

dropin_confirmed() {
    printf '%s\n' "# rgt-ssh-keyonly state=confirmed  (ssh-keyonly.sh 가 관리 — 되돌리기: ssh-keyonly.sh revert)" \
        "# 비밀번호·키보드 대화형 로그인 차단, root 로그인 차단, 공개키만 허용. confirmed_at=$(date '+%F %T %z')" \
        "$SETTINGS"
}

state() {   # none | pending | stale(대기 중 재부팅 -> 무효) | confirmed | foreign(형식 모름)
    local head
    [[ -e $DROPIN ]] || { echo none; return 0; }
    head=$(head -n 1 -- "$DROPIN" 2>/dev/null || true)
    case $head in
        *"rgt-ssh-keyonly state=pending"*)
            if [[ -f $PENDING ]]; then echo pending; else echo stale; fi ;;
        *"rgt-ssh-keyonly state=confirmed"*)
            echo confirmed ;;
        *)  echo foreign ;;
    esac
}

describe_state() {
    case $1 in
        none)      echo "적용 안 됨 (비밀번호 로그인 가능)" ;;
        pending)   echo "적용됨, confirm 대기 (데드맨이 ${WINDOW_TEXT} 뒤 원복)" ;;
        stale)     echo "confirm 전에 재부팅되어 대기 설정이 사라짐 = 비밀번호 로그인 복귀 상태 (apply 부터 다시)" ;;
        confirmed) echo "확정 (키 전용)" ;;
        foreign)   echo "$DROPIN 이 이 스크립트 형식이 아님 — 내용 확인 필요" ;;
    esac
}

ensure_privsep_dir() {   # sshd -t/-T 는 root 로 돌 때 /run/sshd 가 필요 (소켓 활성화로 sshd 가 아직 안 떴으면 없음)
    if [[ -z $ROOT && ! -d /run/sshd ]]; then
        install -d -m 755 /run/sshd
    fi
}

effective() {   # sshd -T 의 관련 4개 값
    ensure_privsep_dir
    sshd -T 2>/dev/null | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) '
}

verify_effective() {   # 4개 설정이 실제로 유효한가 (먼저 읽히는 다른 설정 파일이 덮으면 실패)
    local eff want bad=0
    ensure_privsep_dir
    eff=$(sshd -T 2>/dev/null) || { warn "sshd -T 실패"; return 1; }
    for want in "passwordauthentication no" "permitrootlogin no" "pubkeyauthentication yes"; do
        if ! grep -qx "$want" <<< "$eff"; then
            warn "유효 설정이 '$want' 가 아님: $(grep -E "^${want%% *} " <<< "$eff" || echo '(값 없음)')"
            bad=1
        fi
    done
    if grep -q '^kbdinteractiveauthentication ' <<< "$eff" && ! grep -qx 'kbdinteractiveauthentication no' <<< "$eff"; then
        warn "유효 설정이 'kbdinteractiveauthentication no' 가 아님"
        bad=1
    fi
    if (( bad )); then
        # sshd 는 키마다 "처음 읽은 값"을 쓰고 sshd_config.d/*.conf 는 이름 순(사전순)으로 읽는다 -> 10- 보다 앞선 파일이나
        # Include 줄보다 위의 sshd_config 본문이 범인. 키 전용과 반대되는 값만 보여 줌
        warn "우선하는(먼저 읽히는) 설정 파일 후보 (반대 값):"
        grep -HniE '^[[:space:]]*((PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication)[[:space:]]+yes|PermitRootLogin[[:space:]]+(yes|prohibit-password|without-password|forced-commands-only)|PubkeyAuthentication[[:space:]]+no)([[:space:]]|$)' \
            "$SSHD_DIR"/sshd_config.d/*.conf "$SSHD_DIR/sshd_config" 2>/dev/null | grep -v -- "$DROPIN" | sed 's/^/    /' >&2 || true
    fi
    return $bad
}

check_keys() {   # authorized_keys 에 유효 키 1개 이상 + sshd StrictModes 권한 조건
    local home ak fps n p owner mode bad=0
    home=$(user_home)
    [[ -n $home ]] || die "사용자 '$SSH_USER' 를 찾을 수 없음"
    ak=$ROOT$home/.ssh/authorized_keys
    [[ -f $ak ]] || die "$ak 없음 — 먼저 운영자 공개키를 등록하세요 (PC 에서: ssh-copy-id $SSH_USER@로봇IP)"
    # ssh-keygen -l 은 옵션 접두(from=..., command=...)가 붙은 authorized_keys 형식도 해석하고, 유효한 키 줄만 출력
    fps=$(ssh-keygen -l -f "$ak" 2>/dev/null || true)
    n=$(grep -c . <<< "$fps" || true)
    (( n >= 1 )) || die "$ak 에 유효한 공개키가 없음 — 적용하면 아무도 SSH 로 로그인할 수 없습니다"
    say "$SSH_USER 의 authorized_keys: 유효 키 ${n}개 (이 키들만 로그인 가능해짐)"
    sed 's/^/    /' <<< "$fps"
    # StrictModes: 파일·~/.ssh·홈이 본인/root 소유이고 group/other 쓰기 불가여야 sshd 가 키를 인정함
    for p in "$ak" "$ROOT$home/.ssh" "$ROOT$home"; do
        owner=$(stat -L -c %U -- "$p")
        mode=$(stat -L -c %a -- "$p")
        if [[ $owner != "$SSH_USER" && $owner != root ]] || (( (8#$mode & 8#022) != 0 )); then
            warn "$p : 소유자 $owner, 권한 $mode — sshd(StrictModes)가 이 키를 무시합니다"
            bad=1
        fi
    done
    (( bad == 0 )) || die "권한을 고친 뒤 다시 실행하세요 (예: chmod go-w ~$SSH_USER ~$SSH_USER/.ssh ~$SSH_USER/.ssh/authorized_keys)"
    # 위에서 센 파일을 sshd 가 실제로 읽는가 (AuthorizedKeysFile 을 바꾼 로봇이면 경고 — 새 세션 키 로그인으로 반드시 확인)
    local akf
    ensure_privsep_dir
    akf=$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" { $1 = ""; print }' || true)
    if [[ -n $akf && " $akf " != *" .ssh/authorized_keys "* && " $akf " != *" %h/.ssh/authorized_keys "* ]]; then
        warn "sshd AuthorizedKeysFile =$akf — 위에서 센 $ak 를 읽지 않을 수 있습니다"
    fi
}

check_match_blocks() {   # Match 블록 안에서 비밀번호를 켜면 그 조건의 접속은 전역 설정과 무관하게 비밀번호 허용
    local hits
    hits=$(grep -HnE '^[[:space:]]*Match[[:space:]]' "$SSHD_DIR/sshd_config" "$SSHD_DIR"/sshd_config.d/*.conf 2>/dev/null || true)
    if [[ -n $hits ]]; then
        warn "Match 블록이 있습니다 — 블록 안에서 PasswordAuthentication/KbdInteractiveAuthentication 을 켜면 해당 접속은 여전히 비밀번호가 됩니다:"
        sed 's/^/    /' <<< "$hits" >&2
    fi
}

ssh_unit() {   # 실행 중인 sshd 서비스 (Ubuntu/Debian: ssh.service, 그 외: sshd.service). 없으면 빈 값
    local u
    for u in ssh.service sshd.service; do
        if systemctl is-active --quiet "$u" 2>/dev/null; then
            printf '%s' "$u"
            return 0
        fi
    done
    return 0
}

reload_sshd() {   # SIGHUP: 리스너만 새 설정으로 재실행. 열린 세션은 유지 (Ubuntu ssh.service: KillMode=process, ExecReload 가 sshd -t 선행)
    local u
    u=$(ssh_unit)
    if [[ -z $u ]]; then
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            # Ubuntu 24.04 기본: ssh.socket(Accept=no) 이 22 를 듣다가 첫 접속 때 ssh.service 를 띄움 -> 그때 새 설정을 읽음
            say "ssh.service 는 아직 기동 전 (Ubuntu 24.04 소켓 활성화: ssh.socket 대기) — 다음 접속 때 sshd 가 새 설정으로 기동"
        else
            warn "ssh.service 도 ssh.socket 도 실행 중이 아님 — 지금은 SSH 접속을 받지 않습니다 (설정 파일만 바뀜)"
        fi
        return 0
    fi
    systemctl reload "$u"
}

arm_timer() {
    systemd-run --quiet --unit="$TIMER_UNIT" --on-active="$WINDOW" --timer-property=AccuracySec=1s \
        --description="RGT ssh key-only dead-man revert (confirm not received)" \
        /bin/bash "$REVERT_COPY" revert --from-timer
}

disarm_timer() {   # $1=keep-service: 타이머가 부른 revert 안에서는 자기 서비스를 멈추지 않음
    systemctl stop "$TIMER_UNIT.timer" >/dev/null 2>&1 || true
    if [[ ${1:-} != keep-service ]]; then
        systemctl stop "$TIMER_UNIT.service" >/dev/null 2>&1 || true
    fi
    systemctl reset-failed "$TIMER_UNIT.timer" "$TIMER_UNIT.service" >/dev/null 2>&1 || true
}

remove_files() {   # drop-in 먼저 (sshd 가 없는 Include 를 보더라도 무해하지만 순서를 고정)
    rm -f -- "$DROPIN"
    rm -rf -- "$RUN_DIR"
}

session_started_after() {   # 가장 가까운 sshd 조상(이 명령을 실행 중인 SSH 세션)이 $1(epoch) 이후에 시작됐는가
    local t0=$1 pid=$$ comm et now          # 0: 그렇다  1: SSH 세션이 아님  2: apply 이전부터 열려 있던 세션
    now=$(date +%s)
    while [[ -n $pid && $pid -gt 1 ]]; do
        comm=$(cat "/proc/$pid/comm" 2>/dev/null) || return 1
        if [[ $comm == sshd || $comm == sshd-session ]]; then
            et=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
            [[ -n $et ]] || return 1
            if (( now - et >= t0 )); then return 0; fi
            return 2
        fi
        pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    done
    return 1
}

journal_key_login_since() {   # apply 이후 이 사용자의 공개키 로그인 성공 기록 (마지막 1줄)
    journalctl -q --no-pager -o cat --since "@$1" -t sshd -t sshd-session 2>/dev/null \
        | grep -E "^Accepted publickey for ${SSH_USER} from " | tail -n 1 || true
}

remind_password() {   # $1 = apply (확정 전: 예고만) | confirm (확정 후: 필수 안내)
    if [[ ${1:-} == apply ]]; then
        say "[다음 단계] confirm 으로 확정한 뒤 공유 비밀번호를 교체하세요 (sudo passwd $SSH_USER) — 확정 때 다시 안내합니다"
        return 0
    fi
    cat <<EOF
[ssh-keyonly] [필수] 이제 공유 비밀번호를 교체하세요:  sudo passwd $SSH_USER
              SSH 로는 더 이상 쓰이지 않지만 콘솔 로그인·sudo 에는 그대로 쓰이고, QC 도구·rgt_remote·로봇 측 스크립트 등
              여러 도구에 평문으로 퍼져 있어 사실상 공개된 값입니다. 그 값을 내장한 도구(sudo 용 포함)도 함께 고칠 것.
EOF
}

# ---------------------------------------------------------------- 명령
cmd_status() {
    local st
    st=$(state)
    echo "상태          : $st — $(describe_state "$st")"
    echo "drop-in       : $DROPIN $([[ -e $DROPIN ]] || echo '(없음)')"
    if [[ -f $APPLIED_AT ]]; then
        echo "applied_at    : $(date -d "@$(cat "$APPLIED_AT")" '+%F %T %z' 2>/dev/null || cat "$APPLIED_AT")"
    fi
    echo "데드맨 타이머 : $TIMER_UNIT.timer $(systemctl is-active "$TIMER_UNIT.timer" 2>/dev/null || true)"
    systemctl list-timers --all --no-pager "$TIMER_UNIT.timer" 2>/dev/null | sed -n '1,2p' | sed 's/^/    /' || true
    echo "유효 설정 (sshd -T):"
    effective | sed 's/^/    /' || warn "sshd -T 실패 — 설정 파일 확인 (sshd -t)"
    local home ak
    home=$(user_home)
    ak=$ROOT$home/.ssh/authorized_keys
    if [[ -n $home && -f $ak ]]; then
        echo "authorized_keys: 유효 키 $(ssh-keygen -l -f "$ak" 2>/dev/null | grep -c . || true)개 ($ak)"
    else
        echo "authorized_keys: 없음 ($ak)"
    fi
}

STAGE=""      # apply/confirm 이 파일을 바꾸는 도중인지 (중단·실패 시 EXIT 트랩이 안전한 쪽으로 정리)
RELOADED=0    # apply 가 sshd 에 새 설정을 이미 반영했는지 (그때만 원복 시 다시 reload)

on_exit() {
    case $STAGE in
        applying)    # apply 를 끝내지 못함 -> 키 전용 미적용 상태로 되돌림
            STAGE=""
            disarm_timer
            remove_files
            if (( RELOADED )); then reload_sshd >/dev/null 2>&1 || true; fi
            warn "apply 를 끝내지 못해 원복했습니다 (키 전용 미적용, 비밀번호 로그인 유지)" ;;
        confirming)  # 확정을 끝내지 못함 -> 확인 대기 상태 + 데드맨 재무장 (영구화하지 않음, sshd 는 아직 대기 설정 그대로)
            STAGE=""
            write_file "$DROPIN" 644 "$(dropin_pending)" || true
            arm_timer >/dev/null 2>&1 || warn "데드맨 재무장 실패 — 수동으로 revert 하세요"
            warn "confirm 을 끝내지 못해 확인 대기 상태로 되돌리고 데드맨을 다시 무장했습니다 (${WINDOW_TEXT})" ;;
    esac
}

guard_changes() {   # $1 = applying|confirming. 세션이 끊겨 SIGHUP 을 받아도 EXIT 트랩이 돌도록 신호를 exit 로 바꿈
    STAGE=$1
    trap 'exit 130' INT TERM HUP
    trap on_exit EXIT
}

changes_done() {
    STAGE=""
    trap - EXIT INT TERM HUP
}

cmd_apply() {
    local st
    st=$(state)
    case $st in
        pending)   die "이미 적용되어 confirm 대기 중입니다 — confirm 또는 revert (남은 시간: status)" ;;
        confirmed) say "이미 확정 적용됨 — 변경 없음"; effective | sed 's/^/    /' || true; return 0 ;;
        foreign)   die "$DROPIN 이 이 스크립트 형식이 아님 — 내용을 확인하고 지운 뒤 다시 실행하세요" ;;
        stale)     say "이전 apply 가 confirm 전 재부팅으로 무효화된 상태 — 다시 적용합니다" ;;
    esac
    need_cmd sshd
    need_cmd systemctl
    need_cmd systemd-run
    need_cmd ssh-keygen
    [[ -d $SSHD_DIR/sshd_config.d ]] || die "$SSHD_DIR/sshd_config.d 없음 — 이 sshd 는 drop-in 을 읽지 않습니다"
    check_keys
    check_match_blocks
    ensure_privsep_dir
    sshd -t || die "현재 sshd 설정이 이미 sshd -t 를 통과하지 못함 — 아무것도 바꾸지 않음"

    guard_changes applying                    # 여기부터 실패·중단 = 자동 원복
    disarm_timer                              # 이전 시도의 잔재(실패한 transient 유닛) 정리
    install -d -m 700 "$RUN_DIR"
    write_file "$PENDING" 644 "$(pending_conf)"
    # 사본은 새 파일로 만든 뒤 mv (같은 inode 를 덮어쓰면 그 파일을 실행 중인 bash 가 깨진 내용을 읽음)
    cp -f -- "$SELF" "$REVERT_COPY.new"
    chmod 700 "$REVERT_COPY.new"
    mv -f -- "$REVERT_COPY.new" "$REVERT_COPY"
    write_file "$DROPIN" 644 "$(dropin_pending)"

    sshd -t || die "새 설정이 sshd -t 를 통과하지 못함"
    verify_effective || die "키 전용 설정이 유효하지 않음(다른 설정이 우선함) — 위 파일을 정리한 뒤 다시 실행하세요"
    arm_timer || die "데드맨 타이머를 만들 수 없음 — 안전장치 없이는 적용하지 않음"
    RELOADED=1                                # reload 가 도중에 실패해도 원복 때 다시 reload 해 이전 설정으로 맞춤
    reload_sshd || die "sshd reload 실패"
    date +%s > "$APPLIED_AT"
    changes_done
    journal "apply: key-only pending, dead-man revert in $WINDOW unless confirmed"
    cat <<EOF

==========================================================================================
 SSH 키 전용 적용됨 — 아직 "확인 대기" 상태입니다. 지금 열린 세션은 끊기지 않습니다.
 1) 이 창을 닫지 말고, 새 터미널에서 "키로" 로그인하세요:
      ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no $SSH_USER@<로봇IP>
 2) 그 새 세션에서 ${WINDOW_TEXT} 안에 확정하세요:
      sudo bash $SELF confirm
 ${WINDOW_TEXT} 안에 confirm 하지 않으면(또는 그 전에 재부팅되면) 자동으로 원복됩니다 (비밀번호 로그인 복귀).
 지금 바로 되돌리기: sudo bash $SELF revert
------------------------------------------------------------------------------------------
 [영향] 비밀번호로 SSH 하던 도구(공장 QC 도구, rgt_remote 등)는 이제 접속할 수 없습니다 — 키 방식으로 바꿔야 합니다.
==========================================================================================
EOF
    remind_password apply
}

cmd_confirm() {
    local force=${1:-} st t0 rc=0 line
    st=$(state)
    case $st in
        confirmed) say "이미 확정됨"; effective | sed 's/^/    /' || true; return 0 ;;
        none)      die "적용된 것이 없음 — 먼저 apply" ;;
        stale)     die "confirm 전에 재부팅되어 대기 설정이 사라졌습니다(현재 비밀번호 로그인 가능) — apply 부터 다시" ;;
        foreign)   die "$DROPIN 이 이 스크립트 형식이 아님 — 확인 필요" ;;
    esac
    t0=$(cat "$APPLIED_AT" 2>/dev/null || true)
    [[ $t0 =~ ^[0-9]+$ ]] || t0=$(stat -c %Y -- "$PENDING")   # applied_at 이 없으면 대기 설정을 쓴 시각
    if [[ $force == --force ]]; then
        warn "--force: 키 로그인 확인을 건너뜁니다 — 키로 로그인되는지 확인하지 않은 채 확정합니다"
    else
        session_started_after "$t0" || rc=$?
        if (( rc == 0 )); then
            say "확인: 이 SSH 세션은 apply 이후에 열렸습니다 (키로 로그인한 세션)"
        else
            line=$(journal_key_login_since "$t0")
            if [[ -n $line ]]; then
                say "확인: apply 이후 공개키 로그인 기록 — $line"
            elif (( rc == 2 )); then
                die "이 세션은 apply 이전부터 열려 있던 세션이라 키 로그인이 확인되지 않았습니다.
      새 터미널에서 키로 로그인한 뒤 그 세션에서 confirm 하세요 (확인 없이 강행: confirm --force)"
            else
                die "SSH 세션이 아니고(콘솔 등) apply 이후 공개키 로그인 기록도 없습니다.
      다른 PC 에서 키로 로그인해 확인한 뒤 confirm 하세요 (확인 없이 강행: confirm --force)"
            fi
        fi
    fi

    guard_changes confirming                  # 여기부터 실패·중단 = 확인 대기 상태 + 데드맨 재무장
    disarm_timer                              # 먼저 해제: 확정 도중 타이머가 끼어들어 되돌리지 않게
    write_file "$DROPIN" 644 "$(dropin_confirmed)"
    sshd -t || die "확정본이 sshd -t 를 통과하지 못함"
    verify_effective || die "확정본의 유효 설정이 키 전용이 아님"
    changes_done
    rm -rf -- "$RUN_DIR"
    reload_sshd || warn "sshd reload 실패 — 파일은 확정됨 (다음 sshd 재시작부터 동일하게 적용)"
    journal "confirm: key-only made permanent"
    say "확정: 키 전용 SSH 가 영구 적용되었습니다 (되돌리기: sudo bash $SELF revert)"
    effective | sed 's/^/    /' || true
    remind_password confirm
}

cmd_revert() {
    local from_timer=${1:-} st
    st=$(state)
    if [[ $from_timer == --from-timer ]]; then
        # 늦게 발동한 타이머가 확정된 설정을 되돌리지 않도록: 확인 대기(또는 재부팅 잔재)일 때만 동작
        if [[ $st != pending && $st != stale ]]; then
            say "데드맨 타이머 발동 — 상태가 '$st' 이므로 아무것도 하지 않음"
            disarm_timer keep-service
            return 0
        fi
        journal "dead-man fired: no confirm within $WINDOW -> reverting to password login"
        say "데드맨 타이머 발동: ${WINDOW_TEXT} 안에 confirm 이 없어 원복합니다"
    fi
    if [[ $st == none ]]; then
        disarm_timer
        rm -rf -- "$RUN_DIR"
        say "적용된 것이 없음 — 비밀번호 로그인 상태 그대로 (남은 타이머/임시 파일만 정리)"
        return 0
    fi
    remove_files
    ensure_privsep_dir
    if ! sshd -t; then
        die "drop-in 을 지웠지만 기본 sshd 설정이 sshd -t 를 통과하지 못함 — reload 하지 않음 (실행 중인 sshd 는 이전 설정 유지)"
    fi
    reload_sshd || die "sshd reload 실패"
    if [[ $from_timer == --from-timer ]]; then
        disarm_timer keep-service
    else
        disarm_timer
    fi
    journal "revert: password login restored ($st -> none)"
    say "원복 완료: 비밀번호 로그인이 다시 허용됩니다"
    effective | sed 's/^/    /' || true
}

# ---------------------------------------------------------------- main
case "${1:-}" in
    ""|-h|--help|help) usage; exit 0 ;;
esac
[[ -n $ROOT || $EUID -eq 0 ]] || die "sudo 로 실행하세요"

case "$1" in
    status)  cmd_status ;;
    apply)   take_lock; cmd_apply ;;
    confirm) take_lock; cmd_confirm "${2:-}" ;;
    revert)  take_lock "${2:-}"; cmd_revert "${2:-}" ;;
    *)       usage >&2; exit 2 ;;
esac
