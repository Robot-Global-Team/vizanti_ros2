# vizanti 게이트웨이 운영 가이드

vizanti(SLAM 화면)를 **등록된 패키지 편집기 PC에서만** 열 수 있게 하는 인증 게이트웨이.

3.4.0 부터는 같은 게이트웨이가 network-iface 로봇 API(51231/51233)를 **`/api`** 로 대신 받아 준다 (Bearer 토큰 + 권한).
함께 배포되는 것: 호스트 방화벽 **host guard**, network-iface 노출 모드 **nif.mode**(open/lock), **SSH 키 전용** 전환 도구.

```
[편집기 PC / RCS]                             [로봇]
Ed25519 키쌍 (PC별, 사용자 프로필에 저장)    ┌─ :5000  vizanti_gateway  ← 유일한 외부 노출 (TLS)
                                             │     ├→ 127.0.0.1:5002  flask (server.py)
페어링(1회, 인증서 지문 바인딩)               │     ├→ 127.0.0.1:5001  rosbridge/rws (WS 스플라이스)
→ 챌린지 서명 → OTT → 브라우저 쿠키(2h)      │     ├→ 127.0.0.1:51231 network-iface REST  (/api/nif, Bearer)
→ 챌린지 서명 → API 토큰(15분, Bearer)       │     └→ 127.0.0.1:51233 package HTTP        (/api/pkg, Bearer)
                                             ├─ 5001~5003 외부 차단 (nftables vizanti_guard, IPv6 포함)
                                             └─ host guard (nftables rgt_host_guard): 허용 목록 밖 = 기록(observe) / 차단(enforce)
```

- 로봇에는 **공개키만** 저장 (`~rgt/.rgt_data/vizanti_gateway/clients.json`) — 훔칠 비밀 없음
- 페어링 토큰 = `<코드>-<로봇 인증서 지문 앞 12자리>`. 편집기는 **관측한 인증서 지문이 토큰과 다르면 페어링을 보내지 않고**, 코드 자체는 전송하지 않고 HMAC 증명만 보냄 → 최초 접속 중간자 공격 차단
- 토큰은 **로봇별·1회용·24시간** — 사용 즉시 소모, PC 1대 추가마다 재발급
- 등록 폐기·세션 만료·로그아웃 시 **열려 있는 화면도 30초 내 강제 절단**
- 51231/51233 은 `nif.mode=lock` 이면 루프백 전용 — LAN 호출은 `/api` 만 (그 전까지는 open: 기존처럼 LAN 노출)

## 전제 (반드시 확인)

| 항목 | 요구 |
|---|---|
| 패키지 편집기 | **v1.3.0 이상** (`gateway_client.py` 포함). 구버전 편집기·브라우저 북마크의 `http://ROBOT:5000` 은 실패함 — **편집기를 로봇보다 먼저 배포** |
| rgt_navigation3 | 로봇 bringup 은 `rgt_nav3_launch/launch/vizanti.launch.py` 를 include 함 (`rgt_hard_bringup2/.../hardware_sensors.launch.py`). 이 파일을 **`deploy/nav3_vizanti.launch.py` 내용으로 교체한 3.4.0 nav 패키지**가 함께 배포돼야 함. vizanti_server 단독 교체로는 격리가 적용되지 않고 5000 포트가 충돌함 (설치 스크립트가 검사·중단) |
| 포트 계약 | 루프백 rosbridge 는 **5001 고정** — 탑재 GUI(`rgt_ros2_gui/src/hooks/useRosbridge.ts`)가 `ws://localhost:5001` 을 하드코딩. flask 5002. 게이트웨이 5000 |
| 로봇 OS | Ubuntu 24.04, `python3-cryptography`(ros-jazzy 의존성으로 보통 존재), nftables |
| network-iface | **2.3.0 이상** — `/etc/vizanti/nif.mode` 로 바인드 주소 결정, Origin 가드, 본문 상한 (아래 [nif.mode](#network-iface-노출-모드-nifmode--단계적-전환)) |
| 로봇 API 호출자 | `nif-lock` 전에 51231/51233 을 직접 부르던 도구(편집기·RCS·QC 도구·rgt_remote 등)가 **게이트웨이 `/api` 를 쓰는 버전**이어야 함. 아니면 nif open 유지. 게이트웨이 지원 여부 = `/gw/info` 의 `"api": 1` (1.3.0+) |

## 설치 (로봇에서)

```bash
# 1) 3.4.0 nav 패키지(rgt_navigation3) + vizanti_server 배포, nav 스택 재시작
# 2) 게이트웨이 설치
cd /opt/robot/rgt_ws/common/share/vizanti_server/deploy
sudo bash install_vizanti_gateway.sh          # 인증서·방화벽 유닛·게이트웨이 유닛·첫 페어링 토큰
```

설치 스크립트는 포트 5000 점유(구버전 launch)와 구버전 nav launch 파일 — `/opt/robot/rgt_ws/*/share/rgt_nav3_launch/launch/vizanti.launch.py`(모든 그룹, 정식 위치는 `navigation`)와 `~rgt/test_ws/install` 의 사본(robot-env.sh 가 마지막에 source) — 을 감지하면 **중단**합니다. 마지막에 게이트웨이를 **재시작**하고 `https://127.0.0.1:5000/gw/info` 의 `version` 이 설치본(`vizanti_gateway.py` 의 `VERSION`)과 같은지 20초 안에 확인합니다 — 응답이 없거나 다르면(5000 을 다른 프로세스가 쥠, 유닛이 다른 파일을 실행 등) `journalctl -u vizanti-gateway` 를 보여 주고 실패(exit 1)합니다.

첫 설치는 **아무것도 새로 막지 않습니다**: `/etc/vizanti/nif.mode = open`(51231/51233 기존처럼 LAN 노출) + host guard **observe**(허용 목록 밖은 기록만). 재설치는 운영자가 바꾼 nif.mode·MODE 를 그대로 둡니다. host guard 적용이 실패해도 게이트웨이 설치는 계속됩니다 (경고 후 `host-guard reload`).

Phase 0 (3.3.0 로봇 임시 잠금, 게이트웨이 없이): `sudo bash install_vizanti_gateway.sh firewall-only` → 5000~5003 전부 외부 차단(재부팅 영속). 정식 설치 시 자동 교체 — 두 방향 모두 설치 스크립트가 `vizanti-firewall` 을 `reload-or-restart`(이미 active 면 ExecReload = `nft -f` 한 트랜잭션)로 즉시 다시 적용하고, 커널 룰의 `allow_gateway` 유무(정식 = 있음, Phase 0 = 없음)로 확인합니다.

### 업그레이드·롤백

1. 새(또는 이전) vizanti_server·nav 패키지를 배포한 뒤 그 `deploy/` 의 `sudo bash install_vizanti_gateway.sh` 를 **다시 실행**한다. 매번 방화벽 룰을 다시 적용하고 vizanti-gateway 를 **재시작**한다 (등록·인증서·`/etc/vizanti` 는 유지). 페어링 토큰은 등록된 PC 도 유효한(24h) 대기 토큰도 없을 때(첫 설치)만 발급한다 — 재실행은 대기 중인 토큰(예: RCS 용 `newcode --perms read,drive`)을 덮어쓰지 않고 `[pair] ... 새로 발급하지 않음` 을 출력한다. 새 PC 는 `newcode`(아래 운영 명령). 세션은 메모리에만 있으므로 열린 SLAM 화면은 한 번 끊긴다 → 'SLAM 에디터 열기' 다시.
2. 확인: 설치 출력의 `[unit] vizanti-gateway.service 기동 (version X.Y.Z)`, `journalctl -u vizanti-gateway -b --no-pager | grep listening` 의 마지막 기동 줄(`vizanti_gateway X.Y.Z listening on ...`), `curl -ks https://127.0.0.1:5000/gw/info` 의 `"version"` = `grep '^VERSION' /opt/robot/rgt_ws/common/lib/vizanti_server/vizanti_gateway.py`.
3. 롤백도 같은 절차다. 이전 패키지의 설치 스크립트가 재시작을 하지 않는 버전(`enable --now` 만 함)이면 이미 떠 있는 게이트웨이가 그대로 남으므로 `sudo systemctl restart vizanti-gateway` 후 2) 로 확인한다.

설치 스크립트 하위 명령 (모두 `sudo`, `render` 만 root 불필요):

```bash
D=/opt/robot/rgt_ws/common/share/vizanti_server/deploy
sudo bash $D/install_vizanti_gateway.sh nif-open | nif-lock [--force]
sudo bash $D/install_vizanti_gateway.sh host-guard observe | enforce | off | reload | status | survey [since]
     bash $D/install_vizanti_gateway.sh host-guard render [observe|enforce] [open|lock]   # 미리보기
sudo bash $D/install_vizanti_gateway.sh ssh-keyonly apply | confirm | revert | status   # ssh-keyonly.sh 에 위임
sudo bash $D/install_vizanti_gateway.sh uninstall
```

## 운영 명령 (로봇에서 — **반드시 `sudo -u rgt`**, root 직접 실행 금지)

```bash
GW=/opt/robot/rgt_ws/common/lib/vizanti_server/vizanti_gateway.py
sudo -u rgt python3 $GW newcode          # 새 PC 등록용 1회용 페어링 토큰 (24h) — 기본 권한 ui,read,drive,package (편집기)
sudo -u rgt python3 $GW newcode --perms read,drive          # RCS 등록용 (화면·패키지 권한 없음)
sudo -u rgt python3 $GW list-clients     # 등록된 PC 목록 + 권한 (페어링 직후 name / paired_from 확인 권장)
sudo -u rgt python3 $GW set-perms <id|이름> read,drive       # 권한 변경 (다음 요청부터)
sudo -u rgt python3 $GW revoke <id|이름>  # 등록 폐기 (활성 연결 30초 내 절단)
journalctl -u vizanti-gateway -f         # 인증 성공/실패 로그 (<6> INFO 감사, <4> WARNING 는 스로틀됨)
```

root 로 실행하면 데이터 디렉터리가 `/root` 로 풀려 데몬과 다른 저장소를 보게 되므로 CLI 가 거부합니다.

## 권한 (perms) 과 `newcode --perms`

등록 항목(`clients.json`)마다 권한 목록이 붙는다. 권한은 **페어링 토큰을 만들 때** 정해지고(`newcode --perms`, 코드 옆 `pairing_perms` 파일 0600), 그 토큰으로 페어링한 PC 의 항목에 복사된다 (페어링 프로토콜·증명은 그대로).

| 권한 | 허용하는 것 |
|---|---|
| `ui` | vizanti 화면 (쿠키 세션 `/gw/session`). 없으면 403 `{"error":"forbidden"}` |
| `read` | `/api` 조회 GET (uid, 위치, 상태, 패키지·지도 다운로드 …) |
| `drive` | `/api/nif` 주행 POST (`/navi/request`, `/iface/task` `cruise` `pause` `resume` `stop`) |
| `package` | `/api/pkg` 업로드 POST (`/package/upload`, `/package/start-position/photo`) |

- **편집기**: `newcode` 기본값 = `ui,read,drive,package` (전부). **RCS**: `newcode --perms read,drive` (화면·패키지 업로드 불가).
- 1.3.0 이전에 페어링된 항목(`perms` 없음)은 4개 모두로 취급 — 기존 편집기는 그대로 동작 (`list-clients` 에 `paired before 1.3.0: full access` 표시).
- `newcode read,drive` 처럼 `--perms` 없이 쓰면 전부 허용으로 오해되므로 CLI 가 거부한다 — 반드시 `--perms`.
- `set-perms` / `revoke` 는 **다음 요청부터** 적용: API 토큰의 유효 권한 = "발급 당시 권한 ∩ 현재 등록 권한" 을 매 요청 다시 계산한다. 좁히기·폐기는 즉시(폐기 = 401), 넓히기는 새 토큰부터(토큰 수명 15분 — 클라이언트가 만료 시 자동 재발급). `ui` 를 빼면 열린 화면은 30초 내 절단.
- 주의: `ui` 세션 = rosbridge 전체 권한 (node/kill, set_node_parameter 등 포함). `ui` 는 신뢰하는 편집기 PC 에만.

## 로봇 API (`/api`)

`https://ROBOT:5000/api/nif/<경로>` → `127.0.0.1:51231/<경로>` (network-iface REST), `https://ROBOT:5000/api/pkg/<경로>` → `127.0.0.1:51233/<경로>` (package HTTP). 프로토콜 이름 `rgt-robot-api-v1`.

1. `POST /gw/challenge` → nonce (UI 세션과 같은 저장소, 1회용, IP·client_id 바인딩)
2. 서명 = Ed25519(`b"rgt-robot-api-v1|" + 인증서지문 + b"|" + client_id + b"|" + nonce`) — UI 세션 서명(`vizanti-gw-v2`)과 도메인 분리되어 서로 재사용 불가
3. `POST /gw/api-token {"client_id","nonce","sig"}` → `{"token","ttl":900,"perms":[...],"robot_uid"}`. 토큰은 메모리에만, **발급받은 출발지 IP 에서만** 유효, 클라이언트당 최대 4개(초과 시 가장 오래된 것 폐기)
4. 요청마다 `Authorization: Bearer <token>`, 연결당 요청 1개 (`Connection: close`)

라우트 표 — **정확히 일치**하는 (서비스, 메서드, 경로)만 통과, 나머지는 백엔드에 닿지 않고 404 (`/iface/custom`, Swagger `/`·`/swagger.json`, 모르는 경로·메서드). 진실 소스 = `vizanti_gateway.py` 의 `API_ROUTES` (다른 로봇용 확장: `--api-routes <JSON>`).

| 서비스 | 메서드 | 경로 | 권한 | 본문 상한 | 백엔드 시간 제한 |
|---|---|---|---|---|---|
| nif | GET | `/uid` `/robot_ns` `/navi/info` `/navi/request` `/iface/recent` `/iface/position` `/iface/package` `/iface/vizanti/slam` | read | 0 | 10 s |
| nif | POST | `/navi/request` | drive | 64 KiB | 30 s |
| nif | POST | `/iface/task` `/iface/cruise` `/iface/pause` `/iface/resume` `/iface/stop` | drive | 64 KiB | 30 s |
| pkg | GET | `/package/download` `/package/manifest` `/package/floor` `/package/position` `/package/raw/image` | read | 0 | 30 s |
| pkg | POST | `/package/upload` | package | 8 MiB | 60 s |
| pkg | POST | `/package/start-position/photo` | package | **64 MiB** | 60 s |

응답 코드 (본문 `{"error":"..."}`):

| 코드 | 의미 |
|---|---|
| 400 | 엄격 파싱 위반 (요청줄·헤더 형식, obs-fold, bare CR/LF, NUL·비ASCII, 헤더 64개 초과, Host/Content-Length/Authorization 등 중복, 경로의 `//` `/./` `/../` `%` `\` `;`) |
| 401 | 토큰 없음·만료·다른 IP·폐기 (`WWW-Authenticate: Bearer`) — 클라이언트는 1회 재발급 후 재시도 |
| 403 | `Origin` 헤더가 있음(브라우저 차단) 또는 권한 부족 |
| 404 | 라우트 표에 없음 (백엔드 미접촉) |
| 408 / 411 / 413 | 본문 수신 시간 초과 / Transfer-Encoding 사용·POST 에 Content-Length 없음 / 본문 상한 초과 |
| 503 `Retry-After: 1` | 서비스별 동시 처리 한도(nif 4, pkg 2) 또는 API 연결 한도(전체 32, IP당 8) 초과 — 줄 세우지 않음 |
| 502 / 504 | 백엔드(network-iface) 연결 불가 / 시간 초과 |
| 507 | 디스크 공간 부족 `insufficient_storage` — 게이트웨이가 큰 본문을 임시 저장할 공간, 또는 network-iface 가 사진을 저장할 공간 |
| 500 `spool_failed` | 공간 부족 외의 이유로 게이트웨이가 본문을 임시 저장하거나 다시 읽지 못함 (I/O 오류, fd 부족 등) |

- 백엔드로는 `METHOD /경로?쿼리 HTTP/1.1` + `Host` + `Content-Length` + 클라이언트의 `Content-Type`/`Accept` 만 다시 써서 보냄 — `Authorization`/`Cookie`/`Origin` 은 전달하지 않음. 응답의 `Set-Cookie`/`Access-Control-*`/`Server` 등은 제거, `Cache-Control: no-store` 추가.
- 감사 로그: GET 외 요청은 건마다 `api client=<이름>(<id8>) ip=.. METHOD svc path -> status`, GET 은 묶어서 주기적으로 1줄 (`journalctl -u vizanti-gateway`).

### 사진 업로드 상한 64 MiB

`POST /package/start-position/photo` 만 **64 MiB** (게이트웨이 라우트와 network-iface 51233 양쪽 같은 값). 구버전 편집기가 카메라 원본 PNG(15~30 MB)를 축소 없이 보내기 때문이다. 나머지 업로드(`/package/upload` 등)는 8 MiB.

- 게이트웨이는 본문을 끝까지 받은 뒤 백엔드에 보낸다: 1 MiB 까지 메모리, 그보다 크면 데이터 디렉터리(`~rgt/.rgt_data/vizanti_gateway`)의 이름 없는(unlink 된) 임시 파일 — `MemoryMax=256M` 안에서 동작. 임시 파일 후 여유 공간이 32 MiB 미만이 되면 507.
- **필요한 여유 공간**: 사진 1장에 `/home` 에서 본문의 약 2배 + 32 MiB (64 MiB 사진이면 약 160 MiB). network-iface 가 받는 동안 werkzeug 임시 파일(`/tmp`)과 사진 옆 임시 파일(`~rgt/.ros`)이 함께 있기 때문 — 2배는 `/tmp` 가 `/home` 과 같은 파일시스템일 때이고, 다르면 `/home` 에 본문 + 32 MiB, `/tmp` 에 본문만큼. 모자라면 507 (게이트웨이가 받기 전, 또는 network-iface 가 저장하기 전에 확인).
- 수신 속도 하한: 8 MiB 까지는 32 KiB/s 기준 시간(최대 256 s), 64 MiB 사진은 평균 256 KiB/s 이상이어야 함. 30 s 동안 한 바이트도 안 오면 408.
- pkg 동시 처리 2개 — 큰 사진 업로드 2건이 진행 중이면 다른 pkg 요청은 503(1초 뒤 재시도).

## network-iface 노출 모드 (nif.mode) — 단계적 전환

network-iface(2.3.0+)는 **기동할 때 한 번** 바인드 주소를 정한다 (51231·51233 공통):

| 우선순위 | 값 | 결과 |
|---|---|---|
| 1 | 환경변수 `RGT_NETWORK_IFACE_BIND` = 정확히 `127.0.0.1` / `""` / `0.0.0.0` | 그 값 (긴급 재정의 — nif.mode 는 읽지 않음). 그 밖의 값(`::`, `localhost`, `open`, 앞뒤 공백 등)은 **127.0.0.1 + ERROR (fail-closed)** |
| 2 | `/etc/vizanti/nif.mode` = `lock` | 127.0.0.1 (LAN 호출은 `/api` 만) |
| 2 | `/etc/vizanti/nif.mode` = `open` | 전체 인터페이스 + WARN 로그 |
| 3 | 파일 없음 | 전체 인터페이스 + WARN (2.2.0 동작) |
| 4 | 알 수 없는 내용·읽기 실패 | **127.0.0.1 + ERROR (fail-closed)** |

브라우저 쓰기(`Origin` 이 붙은 GET/HEAD/OPTIONS 외 요청 — Origin 없는 프로그램 호출은 해당 없음)는 두 서버 공통으로, nif.mode 가 아니라 **실제 바인드 주소**로 정한다: 루프백 밖에 바인드돼 있으면(nif.mode open·파일 없음, 또는 env `""`/`0.0.0.0` 긴급 재정의 — lock 이어도) 사설·루프백·공유 주소(`localhost`, 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10(Tailscale), `::1`, fc00::/7, fe80::/10 의 IP 리터럴)에서 연 페이지만 허용하고 공인 주소·호스트명 출처는 403, 루프백에 바인드돼 있으면(lock, fail-closed) `RGT_NETWORK_IFACE_ALLOWED_ORIGINS`(쉼표 목록, 모든 경우에 추가 허용)에 적힌 출처만 허용한다. 51233 은 본문 8 MiB(사진 64 MiB) 초과를 본문을 읽기 전에 413 으로 거절한다.

전환 절차 (open → 조사 → lock):

1. **설치 직후 = open + host guard observe** (기본). 아무것도 끊기지 않는다.
2. **조사**: 며칠 운영 후 `sudo bash install_vizanti_gateway.sh host-guard survey` (기본 최근 7일, 예: `survey "2 days ago"`). `rgt-nif` 행 = **51231/51233 을 LAN 에서 직접 부른 출발지**(IP·포트·활동한 10분 구간 수). 로봇 자신(루프백)은 기록되지 않는다.
   - 범위: `journalctl _TRANSPORT=kernel --since` 로 저널에 남은 **이전 부팅까지** 집계한다 (`-k` 는 현재 부팅만). 머리말에 실제 범위(가장 이른 커널 기록 시각, 부팅 수), **rgt-\* 첫 기록 시각**, host guard 상태(유닛, 테이블, nif.mode)를 찍는다. 기록 규칙은 host guard 안에만 있으므로 그 기간의 빈 칸이 '호출자 없음'이 아닌 경우를 경고한다: 저널이 요청 구간보다 한참 늦게 시작, 첫 rgt-\* 기록이 가장 이른 커널 기록보다 한참 늦음(설치 전 / `host-guard off` / 테이블 삭제), 구간 중 유닛 정지·적용 실패 기록(`journalctl -u vizanti-host-guard` 의 Stopped / Failed to start ~ 다음 적용, 그 기간 표시), **지금** host guard 가 꺼져 있음. 수동 `nft delete table`·`nftables.service` flush 는 유닛 로그에 남지 않으므로 구간 중간의 그런 공백은 드러나지 않는다. 설치 뒤 지난 기간보다 긴 since 를 주면 그 앞은 기록 자체가 없다.
   - 누락: 같은 (출발지, 포트)는 10분에 1줄. `rgt-nif` 는 전용 seen 세트(`seen_nif4/6`)라 다른 포트 스캔에 밀리지 않지만, 한 세트(10분, 8192개)가 가득 찬 동안 새 출발지는 기록되지 않는다. `rgt-guard` 는 출발지마다 초당 1줄(순간 20줄) + 전체 초당 20줄 예산이고, 새 출발지는 초당 20개(순간 100)까지만 출발지 예산 세트(`glog_src4/6`, 10분·8192개)에 들어간다 — 위조 출발지 플러드가 계속되는 동안과 세트가 찬 동안에는 새 출발지가 기록되지 않을 수 있다 (판정에는 영향 없음).
3. 각 호출자를 `/api` 를 쓰는 버전으로 바꾸고 페어링한다 (편집기: 기본 권한, RCS: `newcode --perms read,drive`). 바꿀 수 없는 호출자가 남아 있으면 lock 하지 않는다.
4. **lock**: `sudo bash install_vizanti_gateway.sh nif-lock` — 로컬 게이트웨이가 `/api` 를 제공하는지(`/gw/info "api": 1`) 확인한 뒤에만 잠근다 (확인 생략: `--force`). host guard 도 다시 렌더되어 51231/51233 허용이 빠진다.
5. **network-iface(ROS 스택)를 재시작**해야 바인드가 바뀐다. 확인: `ss -ltn '( sport = :51231 or sport = :51233 )'` → `127.0.0.1` 만.
6. 문제 시 롤백: `sudo bash install_vizanti_gateway.sh nif-open` + network-iface 재시작.

`/etc/vizanti/nif.mode` 를 손으로 고치지 말 것 — host guard 렌더가 따라가지 않는다 (항상 `nif-open` / `nif-lock`).

## 호스트 방화벽 (host guard)

`/etc/vizanti/firewall-host.nft` (`table inet rgt_host_guard`, input 훅 priority 0) — 템플릿 [`firewall-host.nft.in`](firewall-host.nft.in) 을 설치 스크립트가 `/etc/vizanti/host-guard.conf` + `nif.mode` 로 렌더하고, [`vizanti-host-guard.service`](vizanti-host-guard.service)(oneshot, 부팅 시 적용만)가 적용한다. 파일 한 번 적용 = 한 트랜잭션(자기 테이블 delete 후 재생성) — 여러 번 적용해도 누적되지 않고, 바뀌는 순간 무방비 구간도 없다.

허용 목록 (이 순서로 평가):

- `lo` 전부, `ct state established,related` (나가는 연결의 응답·기존 연결), `ct state invalid` 는 drop
- 로봇이 보낸 IPv4 멀티캐스트/브로드캐스트의 루프백 사본 (ROS 2 DDS 로컬 디스커버리)
- ICMP 필수(echo-request, unreachable, time-exceeded, parameter-problem), IGMP, ICMPv6 ND/RA/MLD/packet-too-big
- DHCPv4 응답(udp 67→68), DHCPv6 응답(547→546)
- **5001~5003 은 항상 drop** (vizanti 백엔드 — vizanti_guard 와 이중, HW_NETS·TRUST_IFACES 출발지 포함)
- `HW_NETS` 출발지 전부 — 그 대역이 연결된 NIC 로 들어온 것만 (기본 `10.0.0.0/24 192.168.158.0/24` = MCU UDP 링크, LiDAR. 아래 참조)
- tcp **22** (SSH), tcp **5000** (게이트웨이 — 연결 수·속도 제한은 vizanti_guard 가 priority -10 에서 먼저 적용)
- tcp **51231, 51233 — nif.mode=open 일 때만** (lock 이면 `EXTRA_TCP_PORTS` 로도 열 수 없음 — 렌더러가 거부)
- `EXTRA_TCP_PORTS`, `EXTRA_UDP_PORTS`, `TRUST_IFACES`
- 그 밖 = **observe**: 통과 + `rgt-guard ` 로그 (policy accept) / **enforce**: drop + `rgt-guard-drop ` 로그 (policy drop). 로그는 (출발지, 프로토콜, 목적 포트)당 10분에 1줄, 출발지마다 초당 1줄(순간 20줄), 전체 초당 20줄, 새 출발지는 초당 20개까지 (넘으면 기록 없이 같은 판정 — 카운터 `new-source log cap`). 외부 DDS(UDP 7400+), 다른 서비스 포트 등이 여기에 걸린다.

vizanti_guard(`firewall-vizanti.nft`, priority -10)와의 공존: 같은 훅의 base chain 은 테이블마다 모두 평가되고 **accept 는 그 체인만 끝낸다**. 그래서 host guard 가 22/5000 을 스스로 허용하고, 반대로 host guard 의 accept 는 vizanti_guard 의 drop(5000 연결 상한, 5001~5003)을 무르지 못한다. ufw 가 켜진 로봇은 ufw 체인도 따로 평가된다 (host guard 가 ufw 를 대신하지 않음).

`/etc/vizanti/host-guard.conf` (셸로 source 하지 않음 — `KEY=VALUE` 줄만, 목록은 공백·쉼표 구분):

| 키 | 기본값 | 의미 |
|---|---|---|
| `MODE` | `observe` | `observe` / `enforce` / `off` (`host-guard observe\|enforce\|off` 가 바꿈) |
| `HW_NETS` | `"10.0.0.0/24 192.168.158.0/24"` | 그 NIC 로 들어오면 모든 포트를 허용할 하드웨어망 (IPv4/IPv6 CIDR). `""` = 없음. 로봇에 없는 대역(예: LiDAR NIC 없는 기종의 `192.168.158.0/24`)은 뺄 것 |
| `HW_NETS_STRICT` | `no` | `no` = 렌더할 때 대역마다 직접 연결 경로가 있고 그 대역 주소를 가진 NIC 를 찾아 `iifname` 으로 고정 (못 찾으면 지금 적용된 바인딩 유지, 그것도 없으면 신뢰 안 함). `yes` = 패킷마다 커널 경로 검사(`fib saddr . iif`, 렌더 시점 기본 경로 NIC 제외) — HW 대역의 직접 경로가 있을 때만 위조를 막음 (아래) |
| `EXTRA_TCP_PORTS` / `EXTRA_UDP_PORTS` | `""` | 추가로 열 포트 (`5900 8080-8090`) — survey 로 확인된 정당한 호출만 |
| `TRUST_IFACES` | `""` | 통째로 신뢰할 인터페이스 (`tailscale0`, `docker0`, `tun*`) |

운영 절차 (observe → 조사 → enforce):

1. 고친 뒤 반영: `sudo bash install_vizanti_gateway.sh host-guard reload` (값이 틀리면 렌더·`nft -c` 단계에서 거부되고 **기존 룰 유지**). 미리보기: `host-guard render`. 적용 단계에서 실패하면 `MODE`·`nif.mode`·렌더 파일도 이전 값으로 되돌린다 (부팅 때 적용될 파일 = 지금 커널에 걸린 룰).
2. `host-guard survey` 의 `rgt-guard` 행 = enforce 로 바꾸면 막힐 새 연결. 정당한 것은 위 키로 허용 (예: 컨테이너가 호스트 서비스를 부르면 `TRUST_IFACES="docker0"`, rgt_remote 가 tailscale 이면 `tailscale0`, 로봇이 하드웨어망 DHCP 서버면 `EXTRA_UDP_PORTS="67"`).
3. `sudo bash install_vizanti_gateway.sh host-guard enforce` — 적용 전에 **LAN 에 리슨 중인데 허용 목록 밖인 TCP 포트**를 경고한다 (예: sshd 가 22 가 아닌 포트면 새 SSH 접속이 막힘 → `EXTRA_TCP_PORTS` 에 추가 후 reload). 렌더 단계에서는 HW_NETS 를 경고한다 (경고만 하고 적용은 진행): **NIC 에 묶이지 않은 대역**(MCU·LiDAR 패킷이 막힘), **경로만 있고 대역 주소가 없는 NIC**(VPN·LAN 경로 — 신뢰 안 함), **이전 렌더의 바인딩을 유지한 대역**(렌더 순간 NIC 가 내려가 있었음), **기본 경로 NIC 에 묶인 대역**(사이트망과 겹침 — LAN 위조 우회), STRICT=yes 에서 **직접 경로가 없는 대역** — `bash install_vizanti_gateway.sh host-guard render enforce` 로 미리 확인해 enforce 전에 해결. 기존 연결은 유지되고 새 연결만 판정된다.
4. 상태: `host-guard status` (MODE, nif.mode, 지금 경로·주소 기준 HW_NETS NIC, 커널 룰의 policy·카운터·HW_NETS 규칙, 허용 목록 밖 리슨 포트). 커널 룰의 HW_NETS 바인딩(렌더 시점 값)이 지금 경로·주소와 다르면 대역마다 `경고:` 줄을 찍는다 (STRICT=yes 는 기본 경로 NIC 제외 목록과 직접 경로 유무). 문제 시 즉시 `host-guard observe`.

`HW_NETS` 출발지 위조: Ubuntu 기본 `rp_filter=2`(loose — procps `/etc/sysctl.d/10-network-security.conf`)는 출발지가 **어느** NIC 로든 라우팅되기만 하면 받으므로, LAN 호스트가 출발지를 MCU 주소(예: `10.0.0.200`)로 위조해 LAN NIC 로 보내도 커널이 버리지 않는다. 그래서 host guard 는 HW_NETS 를 주소만으로 신뢰하지 않는다:

- `HW_NETS_STRICT=no`(기본): 렌더(설치·`reload`·모드 전환·nif-open/lock) 때 `ip route` 에서 각 대역의 직접 연결 경로(게이트웨이 경유·default 제외)를 가진 NIC 중 **그 대역과 겹치는 주소를 가진 NIC** 를 찾아 `iifname "<NIC>" ip saddr <대역> accept` 로 렌더한다. 경로만 있고 대역 주소가 없는 NIC(wg-quick 의 `10.0.0.0/8 dev wg0`, 수동 LAN 경로 등)는 신뢰하지 않고 경고한다. 렌더 순간 NIC 를 못 찾으면(링크 다운으로 주소가 빠진 때 등) **지금 적용된 렌더의 바인딩을 유지**하고 경고한다 — 그 NIC 가 지금 기본 경로 NIC 이거나 다른 대역 주소를 가졌으면 유지하지 않는다. 이전 바인딩도 없으면 **신뢰하지 않고** 경고한다 (enforce 에서 그 출발지 패킷은 막힘, 적용은 진행). 부팅은 렌더 없이 같은 파일을 적용하므로 NIC 이름·주소가 바뀌면 `host-guard reload` — `host-guard status` 가 커널 룰의 `iifname` 과 지금 경로·주소 기준 NIC 를 대역별로 비교해 다르면 경고한다.
- `HW_NETS_STRICT=yes`: 렌더 시점 대신 패킷마다 커널 경로로 판정한다 (`fib saddr . iif` = 출발지로 가는 최선 경로의 NIC 로 들어온 것만 — HW NIC 가 늦게 올라오거나 이름이 바뀌어도 따라감). **HW 대역의 직접 경로가 있을 때만 위조를 막는다**: 경로가 없으면(HW NIC 주소가 빠짐·관리 down·NIC 없음) fib 가 다른 경로를 답으로 써서 HW NIC 로 오는 정상 패킷은 막히고, 그 경로의 NIC 로 들어온 위조 출발지는 통과한다 (`rp_filter=1` 도 같음). 기본 경로 NIC 는 렌더 시점 이름으로 제외하므로 현장 LAN 쪽 위조는 막히지만, VPN 등 다른 경로의 NIC 는 제외되지 않고, 기본 경로 NIC 가 바뀌면 `host-guard reload` 해야 한다 (status 가 경고). 로봇에 없는 HW 대역은 HW_NETS 에서 뺄 것.
- 대역이 현장 LAN 과 겹치면(예: 사이트망이 10.0.0.0/24 → LAN NIC 에 그 대역 주소) STRICT=no 는 LAN NIC 에도 묶어 LAN 호스트도 신뢰한다 — enforce 렌더가 "기본 경로 NIC 에 묶임" 으로 경고한다. 범위 좁히기나 `HW_NETS_STRICT=yes` 로는 해결되지 않는다 (좁힌 주소도 LAN 대역 안이고, STRICT=yes 는 경로 우선순위에 따라 MCU 정상 패킷까지 막음). LAN 대역을 포함하지 않게 HW_NETS 를 고치고, 사이트망이 같은 대역이면 그 대역을 HW_NETS 에서 빼고 HW NIC 이름을 `TRUST_IFACES` 에 넣는다. HW NIC 가 내려가 있어 LAN 쪽 경로만 보였던 것이면 올린 뒤 `host-guard reload`.

## SSH 키 전용 전환

[`ssh-keyonly.sh`](ssh-keyonly.sh) — 비밀번호·키보드 대화형·root 로그인을 끄고 공개키만 남긴다. `/etc/ssh/sshd_config.d/10-rgt-keyonly.conf` 에 `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin no`, `PubkeyAuthentication yes`. **10분 데드맨**이 붙어 있어 확인하지 않으면 스스로 원복한다.

절차 (반드시 이 순서):

1. **키 먼저**: 로봇에 SSH 하는 모든 PC·도구의 공개키를 `~rgt/.ssh/authorized_keys` 에 등록 (PC 에서 `ssh-keygen -t ed25519` → `ssh-copy-id rgt@ROBOT`). 비밀번호로만 SSH 하는 도구(rgt_remote, 키 전환 전 QC 도구 등)는 전환 후 접속할 수 없다. 확인: `sudo bash install_vizanti_gateway.sh ssh-keyonly status` (유효 키 개수).
2. **apply** (지금 열린 세션에서): `sudo bash install_vizanti_gateway.sh ssh-keyonly apply`. 다음이면 아무것도 바꾸지 않고 거부: authorized_keys 에 유효 키 0개, 홈·`.ssh`·파일 권한이 group/other 쓰기 가능(StrictModes), 현재 설정이 `sshd -t` 실패. 적용 후 `sshd -T` 로 유효 설정을 다시 확인해 다른 설정이 이기면 자동 원복한다. 반영은 `systemctl reload ssh` — **열린 세션은 끊기지 않는다**.
3. **이 창을 닫지 말고 새 터미널에서 키로** 로그인: `ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no rgt@ROBOT`
4. **그 새 세션에서 10분 안에** `sudo bash install_vizanti_gateway.sh ssh-keyonly confirm`. confirm 은 "이 세션이 apply 이후에 열렸거나, apply 이후 공개키 로그인 기록(journal)이 있음"을 확인한 뒤 영구화한다 (확인 생략 `confirm --force` — 권장하지 않음). 10분 안에 confirm 하지 않으면(또는 그 전에 재부팅되면) **비밀번호 로그인으로 자동 복귀**.
5. **확정 후 공유 비밀번호 교체**: `sudo passwd rgt`. SSH 에는 더 이상 쓰이지 않지만 콘솔 로그인·sudo 에 쓰이고 여러 도구에 평문으로 퍼져 있다 — 같은 값을 내장한 도구(rgt_remote, 로봇 측 sudo 용 스크립트 등)도 함께 고칠 것.

동작 세부:

- **우선순위**: sshd 는 키마다 **처음 읽은 값**을 쓴다. Ubuntu `sshd_config` 는 첫 줄의 `Include /etc/ssh/sshd_config.d/*.conf` 를 **파일 이름 사전순**으로 읽으므로 `10-rgt-keyonly.conf` 가 `50-cloud-init.conf`(클라우드 이미지의 `PasswordAuthentication yes`)와 `sshd_config` 본문보다 먼저 이긴다. 10- 보다 앞선 이름(`00-` `05-` …)에 반대 값이 있으면 apply 가 감지해 원복하고 그 파일·줄을 보여 준다. `Match` 블록이 있으면 경고(블록 안에서 비밀번호를 켜면 그 조건의 접속은 여전히 비밀번호).
- **재부팅 안전**: confirm 전에는 drop-in 에 `Include /run/rgt-ssh-keyonly/pending.conf` 한 줄만 있고 실제 설정은 `/run`(tmpfs)에 있다. 재부팅하면 `/run` 이 비고 sshd 는 없는 Include 를 무시하므로 비밀번호 로그인이 돌아온다 (`status` = `stale`, 다시 apply 부터). confirm 하면 설정이 drop-in 에 직접 기록된다.
- **데드맨**: `systemd-run --on-active=10min --unit=rgt-ssh-keyonly-revert … revert --from-timer`. confirm 이 먼저 타이머를 멈춘다. 늦게 발동한 타이머는 확정된 설정을 건드리지 않는다. apply/confirm/revert(타이머 포함)는 `/run/rgt-ssh-keyonly.lock` 으로 직렬화.
- **Ubuntu 24.04 소켓 활성화**: `ssh.socket` 이 22 를 듣다가 첫 접속 때 `ssh.service` 를 띄운다. ssh.service 가 아직 안 떠 있으면 reload 대신 "다음 접속 때 새 설정으로 기동" 으로 처리한다. reload = `sshd -t` 후 SIGHUP (`KillMode=process` — 기존 세션 유지). restart 하지 않는다.
- `status`: 상태(none/pending/stale/confirmed), `sshd -T` 의 4개 값, 데드맨 타이머, authorized_keys 유효 키 수. `revert`: drop-in 삭제 → `sshd -t` → reload.

## vizanti node/start 허용 패키지 (`node_start_allowed_packages`)

vizanti 의 `vizanti/node/start` 서비스(service_handler.py)는 `ros2 run|launch <설치된 패키지> <이름> [인자:=값 …]` 만 실행한다. 파라미터 `node_start_allowed_packages` 는 **기본 빈 값 = 설치된 모든 패키지 허용**이다 (3.4.0 기본 그대로). 화면(`ui` 권한)으로 띄울 패키지를 좁히려면 [`nav3_vizanti.launch.py`](nav3_vizanti.launch.py)(로봇에서는 `rgt_nav3_launch/launch/vizanti.launch.py`) 의 include **앞에** 전역 파라미터를 둔다:

```python
from launch_ros.actions import SetParameter
from launch_ros.parameter_descriptions import ParameterValue
...
    return launch.LaunchDescription([
        # vizanti/node/start 허용 패키지 (쉼표 목록, "" = 설치된 모든 패키지)
        SetParameter(name="node_start_allowed_packages",
                     value=ParameterValue("pkg_a,pkg_b", value_type=str)),
        vizanti,
    ])
```

- include 된 vizanti_server.launch.py 의 노드 전부에 전달되지만 이 이름을 선언하는 노드는 service_handler 뿐이다 (다른 노드는 무시). `value_type=str` 은 패키지 이름 하나가 숫자·`true` 처럼 해석되는 것을 막는다.
- 바인드 주소·포트는 이 파일에서 덮어쓰지 말 것 (설치 스크립트가 `"0.0.0.0"` / `"address": ""` / `default=5000)` 를 찾으면 구버전으로 보고 중단).
- 반영: nav 스택 재시작. 확인: `ros2 param get /vizanti_service_handler_node node_start_allowed_packages`.

## 검증

로봇에서:
```bash
ss -ltnp | grep -E '(0\.0\.0\.0|\[::\]|\*):5000'   # 외부 노출 5000 = vizanti_gateway.py 뿐
ss -ltn  | grep -E '127\.0\.0\.1:500[12]'          # flask 5002 / rosbridge 5001 루프백만
nft list table inet vizanti_guard
nft list table inet rgt_host_guard                 # host guard (policy accept = observe / drop = enforce)
ss -ltn '( sport = :51231 or sport = :51233 )'     # nif lock: 127.0.0.1 만 / open: * 또는 [::]
sudo bash install_vizanti_gateway.sh host-guard status
sudo bash install_vizanti_gateway.sh ssh-keyonly status
```
편집기 없는 PC(LAN)에서:
```bash
curl -ks https://ROBOT:5000/                 # 401 안내 페이지만 (502 면 nav 미기동)
curl -ks https://ROBOT:5000/ros_launch_params # 401 (JSON 미노출)
curl -s --max-time 3 http://ROBOT:5001/ ; curl -s --max-time 3 http://ROBOT:5002/  # 연결 불가
wscat -n -c wss://ROBOT:5000/                # 401 즉시 종료
curl -ks -o /dev/null -w '%{http_code}\n' https://ROBOT:5000/api/nif/uid   # 401 (토큰 없음)
curl -s --max-time 3 http://ROBOT:51231/uid  # nif lock 후: 연결 불가 (open 이면 응답)
```
페어링된 편집기에서: 네트워크 > SLAM 에디터 열기 → (최초 1회 토큰 입력) → 브라우저에 지도. 인증서 경고는 PC(브라우저 프로필)당 1회 통과 — 접속 링크는 **3분** 안에 열어야 함.

## 개발 모드 (게이트웨이 없이)

```bash
ros2 launch vizanti_server vizanti_server.launch.py port_public:=5001
# 브라우저: http://127.0.0.1:5002  (페이지가 ws://127.0.0.1:5001 로 직접 연결)
```

## 롤백

- **긴급 열람 (재시작 불필요, 게이트웨이 고장 시)**: PC 에서
  `ssh -L 5002:127.0.0.1:5002 -L 5000:127.0.0.1:5001 rgt@ROBOT` 후 `http://127.0.0.1:5002` 열기
  (페이지는 `ws://127.0.0.1:5000` 으로 붙고 터널이 rosbridge 5001 로 보냄)
- **게이트웨이만 제거**: `sudo bash install_vizanti_gateway.sh uninstall` → 유닛·방화벽(vizanti_guard, host guard) 제거, 등록 데이터와 `/etc/vizanti`(nif.mode, host-guard.conf) 보존. 백엔드는 루프백에 남아 **어떤 PC 도 접속 불가(fail-closed)** — 의도된 안전 기본값. nif.mode 가 lock 이면 51231/51233 도 LAN 에서 닿지 않으므로 필요하면 `nif-open` + network-iface 재시작
- **완전 롤백**: 위 uninstall 후 nav 패키지(rgt_nav3_launch) 를 3.3.0 으로 되돌림 → vizanti 가 다시 0.0.0.0 에 무인증 노출됨(3.3.0 상태). rws 변형을 쓰는 로봇은 uninstall 전에 nav 를 먼저 내릴 것 (nft 삭제 즉시 5001 이 노출)
- **nif lock 되돌리기**: `sudo bash install_vizanti_gateway.sh nif-open` + network-iface(ROS 스택) 재시작 (`nif-open` 이 host guard 도 다시 렌더). 설치 스크립트를 쓸 수 없을 때의 긴급 재정의: network-iface 프로세스 환경에 정확히 `RGT_NETWORK_IFACE_BIND=0.0.0.0` (공백·`::` 등 다른 값은 127.0.0.1 로 fail-closed) 후 재시작 (nif.mode 보다 우선). 기동 로그에 `fail-closed` ERROR 가 없고 `ss -ltn` 에 0.0.0.0:51231/51233 이 보이는지 확인. 단 host guard 가 **enforce** 면 룰이 nif.mode(lock)로 렌더돼 있어 51231/51233 새 연결은 계속 drop 된다 — 함께 `sudo systemctl disable --now vizanti-host-guard` (ExecStop 이 테이블을 지우고 재부팅 후에도 해제 유지). 일시 해제만 하려면 `sudo nft delete table inet rgt_host_guard` (재부팅 시 다시 적용) — 아래 host guard 되돌리기 참조
- **host guard 되돌리기**: `host-guard observe` (즉시 차단 중지, 기록은 계속) 또는 `host-guard off` (테이블 삭제·유닛 비활성). 스크립트 없이: `sudo nft delete table inet rgt_host_guard` (재부팅 시 다시 적용됨 — 영구 해제는 `sudo systemctl disable --now vizanti-host-guard`)
- **SSH 키 전용 되돌리기**: `ssh-keyonly revert`. SSH 로 들어갈 수 없으면 콘솔(비밀번호 로그인은 콘솔에서 계속 유효)에서 같은 명령, 또는 `sudo rm /etc/ssh/sshd_config.d/10-rgt-keyonly.conf && sudo systemctl reload ssh`. confirm 전이면 10분 뒤 자동 원복, 재부팅해도 원복
- **권한·등록**: `set-perms <id|이름> <목록>` / `revoke <id|이름>` (다음 요청부터)

## 알려진 한계 (운영 수용 사항)

- 자가서명 TLS → 브라우저 경고 1회/로봇·프로필 (추후 RCS CA 로 해소 예정)
- 신뢰 단위는 **PC(디바이스)** — PC 의 개인키 파일 유출 = 그 PC 몫의 접근권 유출. 대응은 `revoke`
- 편집기는 로봇을 **IPv4 리터럴**로 지정 (호스트명/mDNS 금지) — nonce/OTT/세션이 소스 IP 에 바인딩됨. PC IP 가 바뀌면 'SLAM 에디터 열기' 재클릭
- `base_url` 은 `''` 만 지원 (게이트웨이가 `/` 로 리다이렉트)
- `--no-tls` 운용 시 LAN 스니핑으로 세션 쿠키·페어링 증명 재생 가능 — 기본값 TLS-on 유지
- ufw 활성 로봇: ufw 정책은 별도 평가됨 → 설치 스크립트가 `5000/tcp allow` 를 추가/제거
- 51231/51233(network-iface) 은 `nif.mode=lock` + `/api` 로, 외부 DDS 는 host guard **enforce** 로 막는다 — 둘 다 단계적 전환 전(open / observe)에는 기존처럼 열려 있음. `HW_NETS` 가 현장 LAN 과 겹치면 그 LAN 에서 오는(또는 그 대역으로 위조한) UDP 는 enforce 에서도 통과하고, `HW_NETS_STRICT=yes` 에서 HW 대역의 직접 경로가 없을 때는 그 출발지로 가는 다른 경로(VPN 등)의 NIC 로 온 위조가 통과 (위 HW_NETS 참조). 로봇 내부 DDS(루프백·공유메모리)는 범위 밖
- `ui` 세션 = rosbridge 전체 권한 (node/kill, set_node_parameter …) — rosbridge op·서비스 허용목록은 별도 과제
- host guard 는 **input 훅만** 다룬다: Docker 가 publish 한 컨테이너 포트(DNAT → FORWARD 경로)는 대상이 아님. IPv6 로 루프백되는 로컬 멀티캐스트(IPv6 DDS)는 열지 않음 (observe 로그로 먼저 확인)
- `nftables.service` 를 start/restart 하면 `/etc/nftables.conf` 의 `flush ruleset` 이 vizanti_guard·rgt_host_guard 를 지운다 → `sudo systemctl restart vizanti-firewall vizanti-host-guard`
