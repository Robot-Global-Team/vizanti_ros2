# Vizanti gateway 1.5.1 — 접속 코드 PAKE 등록 / NIF device authority

## 패키지와 게이트웨이 버전 관리

`vizanti_server/package.xml`의 ROS 패키지 버전과 `scripts/vizanti_gateway.py`의 `VERSION`은 모두 **1.5.1**이며, 배포할 때 같은 `MAJOR.MINOR.PATCH`로 함께 변경합니다. 전체 로봇 SW 릴리스 번호와 다른 Vizanti ROS 패키지의 버전은 별도로 관리합니다. CMake configure는 두 값이 다르면 실패하며, 정식 게이트웨이 설치기도 의존성 설치·서비스·방화벽 변경 전에 설치된 패키지와 게이트웨이의 버전 일치를 검사합니다.

`colcon build --packages-select vizanti_server`로 패키지를 빌드·설치하면 `share/vizanti_server/package.xml`과 `share/vizanti_server/cmake/vizanti_serverConfig{,-version}.cmake`가 함께 생성됩니다. 스크립트만 교체하는 부분 업데이트에서도 이 세 메타데이터 파일을 함께 배포해야 ROS 조회·CMake 의존성 검색·`/gw/info`가 같은 버전을 표시합니다. 메타데이터만 갱신할 때 게이트웨이 재시작은 필요하지 않습니다.

기본 인증 방식은 `nif-device-v1`입니다. network-iface 인증 서비스가 등록 기기, 코드, 서명 챌린지와 세션을 관리합니다. 운영 모드는 별도의 `clients.json`/`pairing_code`를 등록 권위로 사용하지 않습니다. 로컬 회귀 시험에서 명시하는 `--auth-mode legacy`는 아래 로봇 운영 설치 모드가 아닙니다. 저장소의 전체 구성은 [루트 README](../../ReadMe.md)를 참조합니다.

```text
PC private key → HTTPS :5000 (certificate verified)
                ├─ /gw/enroll/start → confirm → commit (동일 TLS 1.3 연결)
                ├─ /gw/enroll/result, challenge, api-token, session
                │       → UID-checked /run/rgt-network-iface/gateway.sock
                │       → NIF: ~/.ros/.setting/devices.json (public keys only)
                ├─ /api/nif/* → 127.0.0.1:51231 + NIF bearer authorization
                ├─ /api/pkg/* → 127.0.0.1:51233 + NIF bearer authorization
                └─ Vizanti HTTP/WebSocket → loopback :5002/:5001
```

## 등록과 사용

- 로봇의 NIF 로컬 제어 소켓으로 공용 비밀번호를 검증한 뒤 8자리 접속 코드를 발급합니다. 코드의 유효기간은 60초이며 한 기기 등록에 성공하면 소모됩니다. 이 변경에는 로봇 GUI를 포함하지 않습니다. GUI를 구현하기 전에는 NIF의 `rgt-nif-auth` CLI를 사용합니다.
- 신규 클라이언트는 IP와 8자리 코드로 `spake2-tls-exporter-v2` 등록을 수행합니다. 고정한 AWS-LC SPAKE2 draft-02 엔진과 실제 TLS 1.3 exporter로 로봇/PC가 코드를 알고 있는지 상호 확인합니다. 인증서 지문을 사용자가 입력하지 않으며, 인증서를 그냥 승인하거나 HMAC 방식으로 자동 전환하지 않습니다. RFC9382/FIPS 또는 신규 통합의 독립 보안 감사 완료를 주장하지 않습니다.
- `/gw/enroll/start`, `/gw/enroll/confirm`, `/gw/enroll/commit`은 동일 TLS 연결에서 정확한 순서로 세 번만 허용합니다. gateway가 실제 exporter·연결 ID·인증서 지문·원본 IP를 NIF 소켓에 삽입하며 HTTP JSON의 동명 필드는 무시합니다. 인증서 해시만으로 exporter를 대체하지 않습니다.
- PC는 교환 전에 개인키/요청 ID를 저장하고, 서버 확인값 검증 후 인증서 pin을 영구 저장한 다음 commit을 제출합니다. commit 응답을 잃으면 정상 pin 검증 연결에서 `/gw/enroll/result`로 동일한 완료 요청만 조회합니다. 코드나 HMAC 증명을 다시 보내지 않습니다. 이미 등록된 PC의 키·ID와 기존 토큰 로그인은 유지됩니다.
- 등록 기기는 코드 없이 개인키로 자동 재인증합니다. API 토큰 15분/UI 세션 2시간은 통신 세션의 수명이며 영구 등록의 수명이 아닙니다. 로봇/NIF 재시작 후에도 등록은 유지되며 새 챌린지로 토큰을 받습니다.
- 기본 발급 권한은 `read,package`입니다. `ui`/`drive`는 운영자가 명시적으로 허용해야 합니다. Vizanti/rosbridge의 `ui` 권한은 주행을 포함한 광범위한 로봇 제어를 가능하게 하므로 일반 읽기 권한으로 취급하지 마세요.
- 기기 폐기, 토큰 만료, NIF 재시작/장애 시 새 요청은 인증에 실패합니다. 활성 HTTP/WebSocket/API 연결은 각 순회에서 최대 1초 대기한 뒤 배치 확인하며 RPC 전체 제한은 별도로 2초입니다. 연결 종료는 보통 약 3초이고 통합 검증 목표는 5초이며, CPU·네트워크 전체 고갈에서도 절대적인 실시간 종료를 보장한다는 의미는 아닙니다. NIF가 응답하지 않으면 보호 API는 503으로 종료하며 무인증 모드로 전환하지 않습니다.
- 정적 UI HTTP는 `GET`/`HEAD` 한 건마다 인증하고 `Connection: close`로 중계합니다. 요청 본문, Transfer-Encoding 및 파이프라인 후속 요청을 백엔드로 전달하지 않습니다. WebSocket만 양방향 중계를 유지합니다.
- `/gw/info`는 `auth_mode=nif-device-v1`을 유지하고 TLS backend와 NIF native 엔진이 준비됐을 때만 `enrollment_protocols=["spake2-tls-exporter-v2"]`를 광고합니다. 미준비 상태에서 신규 등록은 실패하며 기존 로그인은 유지됩니다. 등록/로그인 경로의 HTTP 접속 가능 여부가 보호 기능 사용 권한을 뜻하지 않습니다.

신규 PC는 IP와 8자리 코드만 입력하며 사용자가 인증서 지문을 수동으로 입력하지 않습니다. 앱이 PAKE로 확인한 pin은 외부 브라우저의 인증서 저장소에 자동 설치되지 않으므로, Vizanti SSO에 사용할 브라우저의 인증서 신뢰는 별도로 구성합니다. 인증된 앱이 일회용 SSO 링크를 발급받아 `https://<robot-ip>:5000`의 UI를 엽니다.

New PCs enter only the IP and eight-digit code; no manual certificate fingerprint is required. An app's PAKE-authenticated pin does not provision an external browser's trust store. Configure browser certificate trust separately and open the UI using the single-use SSO link issued to a `ui`-authorized app over HTTPS port 5000.

## 1.5.1 가용성·요청 경계 보강

- TCP 수락 시점부터 TLS 슬롯 대기, transport 연결과 핸드셰이크 완료까지 **총 5초**만 허용합니다. TLS 객체는 슬롯을 확보한 뒤 생성하고, 시간 초과·취소·늦은 transport 연결의 socket/slot/접속 수를 회수합니다. 기존 전체 256개/접속원 32개 연결 상한과 동시 TLS 16개 제한은 유지합니다. HTTP 헤더 2초, PAKE 전체 60초, 업무 API의 기존 업로드 제한은 별도이며 5초로 줄이지 않습니다.
- 공개 정보·로그인·UI·API와 PAKE 후속 요청 모두 라우팅 전에 HTTP/1.1, origin-form, 유효한 단일 Host, 헤더 구문과 framing을 검사합니다. Authorization/Cookie/Content-Length 등 보안 헤더의 중복, 잘못된 길이와 Transfer-Encoding을 거부합니다. Accept/Connection 등 반복 가능한 목록 헤더와 정상 WebSocket은 허용합니다. 요청 헤더는 수신 조각과 관계없이 마지막 CRLFCRLF를 포함해 **16,384바이트** 이하입니다.
- 인증·등록의 접속원은 실제 TCP 소켓의 정규화된 IP입니다. JSON의 `peer_ip`나 X-Forwarded-For로 대상을 바꿀 수 없습니다. 업무 backend의 기존 token-only validate 계약은 유지합니다. NIF의 단기 제한 응답은 안정된 오류 이름, HTTP `Retry-After`와 선택적 JSON `retry_after_seconds`(1~600초)로 전달합니다. 서비스 장애는 무인증 경로로 전환하지 않고 503으로 닫습니다.
- 함께 배포하는 NIF 보완은 서명 로그인·완료 결과 복구의 실패가 정상 기기 전체를 장시간 잠그는 경로를 분리합니다. PAKE의 로봇 전체 **5회/600초 선차감**과 60초·1회 코드 정책은 그대로 유지합니다. 접속원별 진입 제어는 임시 세션의 병렬 선점을 완화하며, 공용 Wi-Fi에서 순차적·다중 주소 등록 예산 소진을 완전히 막지는 못합니다. 등록망 분리 정책은 별도 운영 결정이며 이 업데이트는 방화벽·라우터·GUI 정책을 변경하지 않습니다.

## 로봇 설치

현재 통합 기준은 ROS 2 Jazzy / Ubuntu 24.04입니다. `network-iface`와 native `rgt_pake` 라이브러리, `vizanti_server`, 시스템 Python의 `cryptography`·`pyOpenSSL`, 루프백 내비게이션 launch가 함께 필요합니다. NIF REST/package 서버에도 Bearer 인증 미들웨어를 배포합니다. 내비게이션은 Flask `127.0.0.1:5002`와 rosbridge `127.0.0.1:5001`을 실행해야 합니다. NIF native 엔진의 고정 빌드·준비 절차는 [network-iface README](https://github.com/Robot-Global-Team/network-iface/blob/feat/code-only-enrollment/README.md)를 참조합니다.

installer는 패키지/게이트웨이 버전과 pyOpenSSL exporter API를 검사하고, 의존성이 없으면 Ubuntu 패키지 설치를 시도합니다. 오프라인 로봇은 먼저 필요한 의존성을 준비합니다. 아래 순서는 **인증서가 없는 최초 로봇까지 포함**합니다. 기존 로봇에서는 인증서·개인키·등록 목록·보안 상태를 보존합니다. 운영 유지보수 시간에 실행하고 코드 발급·등록·폐기를 병행하지 않습니다.

The current integration targets ROS 2 Jazzy / Ubuntu 24.04. Prepare the NIF native engine, authenticated NIF HTTP servers, matching Vizanti package/gateway, system Python dependencies and loopback navigation launch. The sequence below also works for an initial robot without a certificate. Preserve existing certificate/key/registry/state on an installed robot and do not perform concurrent issuance/enrollment/revocation during maintenance.

### 1. 로봇별 TLS 인증서 먼저 준비 / Prepare the robot TLS identity first

로봇의 **일반 `rgt` 계정**에서 단일 관리자가 실행합니다. 새 인증서는 인증 서비스의 최초 기동 전에 준비합니다. NIF 설치기는 인증서가 이미 있어야 하며, 아래 명령은 게이트웨이 installer와 같은 EC P-256·자가 서명·3,650일 설정을 사용합니다. 기존 인증서와 키는 재생성하지 않습니다. 한쪽 파일만 있거나 심볼릭 링크이면 중단하고 설치 상태를 먼저 확인합니다. 생성 실패도 다음 단계로 진행하지 않습니다. 두 파일의 생성 전체가 하나의 원자적 파일 연산인 것은 아니므로 중단 후 부분 파일을 자동으로 덮어쓰지 않습니다. 개인키의 내용을 출력하지 않습니다.

Run as the unprivileged robot `rgt` account with one administrator, preparing a new identity before first authority startup. This uses the gateway installer's EC P-256/self-signed/3,650-day parameters. Existing files are preserved; an incomplete or symlinked pair is rejected. Generation failure stops the sequence. Pair creation is not one atomic filesystem operation, so a partial pair is not automatically overwritten on retry. Private-key contents are never printed.

```bash
[[ $(id -un) == rgt ]] || { printf '%s\n' 'Run this preparation as rgt' >&2; exit 1; }
umask 077
task_tls_dir=/home/rgt/.rgt_data/vizanti_gateway
install -d -m 0700 "$task_tls_dir" || exit 1
if [[ -e "$task_tls_dir/tls_cert.pem" || -L "$task_tls_dir/tls_cert.pem" || -e "$task_tls_dir/tls_key.pem" || -L "$task_tls_dir/tls_key.pem" ]]; then
    [[ -f "$task_tls_dir/tls_cert.pem" && ! -L "$task_tls_dir/tls_cert.pem" && -f "$task_tls_dir/tls_key.pem" && ! -L "$task_tls_dir/tls_key.pem" ]] || { printf '%s\n' 'Incomplete or unsafe TLS identity; inspect before continuing' >&2; exit 1; }
    printf '%s\n' 'Existing robot certificate/key preserved'
else
    task_robot_uid=$(cat /rgt/robot_uid 2>/dev/null || printf '%s' unknown)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$task_tls_dir/tls_key.pem" -out "$task_tls_dir/tls_cert.pem" \
        -days 3650 -nodes -subj "/CN=vizanti-gw-${task_robot_uid}" \
        || { printf '%s\n' 'TLS generation failed; inspect partial files before continuing' >&2; exit 1; }
    chmod 0600 "$task_tls_dir/tls_cert.pem" "$task_tls_dir/tls_key.pem" || exit 1
fi
```

### 2. NIF 인증 권위 설치·시작 / Install and start the NIF authority

준비한 `network-iface` 소스 루트에서 실행합니다. `src/native/librgt_pake.so`와 LICENSE/NOTICE가 준비되어 있어야 합니다. `--start`가 설치 후 서비스를 시작하고 `/run/rgt-network-iface/{control,gateway,admin}.sock`을 준비합니다. 등록 목록은 `rgt` 기준 `/home/rgt/.ros/.setting/devices.json`, 상태는 같은 폴더의 `nif-auth-state.json`입니다.

Run from the prepared `network-iface` source root, including its native library and notices. `--start` installs and starts the authority; the daemon creates its control/gateway/admin sockets. Existing persistent registration and security state are retained.

```bash
# network-iface 소스 루트 / source root
sudo bash deploy/install_auth.sh --user rgt \
    --cert /home/rgt/.rgt_data/vizanti_gateway/tls_cert.pem --start
systemctl is-active network-iface-auth.service
rgt-nif-auth status
```

### 3. 게이트웨이·방화벽 설치 / Install the gateway and port guards

ROS 패키지·CMake 버전 메타데이터·게이트웨이를 함께 배포한 뒤 실행합니다. 아래 명령은 NIF가 **동일 인증서로 실제 응답하는지** 검사하고 게이트웨이와 방화벽 서비스를 설치합니다. 첫 설치에서 없는 설정은 `nif.mode=lock`, host guard `MODE=enforce`로 생성합니다. 기존 설정은 보존하므로 아래 두 모드 명령으로 운영 정책을 명시적으로 확인·적용합니다. host guard 적용 실패는 설치 성공으로 처리하지 않습니다.

After deploying the package, CMake version metadata and gateway together, run the installed gateway installer. It checks that NIF actually responds using the same certificate before proceeding. Missing configuration starts as lock/enforce; existing configuration is preserved, so explicitly apply the intended operational modes.

```bash
sudo bash /opt/robot/rgt_ws/common/share/vizanti_server/deploy/install_vizanti_gateway.sh
sudo bash /opt/robot/rgt_ws/common/share/vizanti_server/deploy/install_vizanti_gateway.sh nif-lock
sudo bash /opt/robot/rgt_ws/common/share/vizanti_server/deploy/install_vizanti_gateway.sh host-guard enforce
```

`nif.mode`의 바인드 주소는 NIF HTTP 노드가 기동할 때 읽습니다. 처음 lock으로 변경했다면 승인된 유지보수 절차에서 해당 노드를 재기동하여 적용하고, `ss`로 실제 리슨 주소를 확인합니다. 설정 파일만 바꾼 것을 루프백 적용 완료로 판단하지 않습니다. 하드웨어망·추가 예외·SSH 등 정당한 운영 경로는 enforce 적용 전에 검토합니다.

NIF HTTP nodes read their bind mode at startup. When first switching to lock, restart the affected nodes through the approved maintenance procedure and verify actual listeners. A changed configuration file alone does not prove loopback binding. Review legitimate hardware/extra/SSH operational paths before enforcing the host guard.

### 4. 정상 상태 확인 / Verify normal readiness

```bash
sudo systemctl status network-iface-auth vizanti-gateway
systemctl is-enabled network-iface-auth vizanti-gateway vizanti-host-guard vizanti-firewall
ss -ltn '( sport = :5000 or sport = :5001 or sport = :5002 or sport = :51231 or sport = :51233 )'
curl -ks https://127.0.0.1:5000/gw/info
curl -ks -o /dev/null -w '%{http_code}\n' https://127.0.0.1:5000/api/nif/uid
```

`/gw/info`는 `version=1.5.1`, `auth_mode=nif-device-v1`, `enrollment_protocols=["spake2-tls-exporter-v2"]`를 반환해야 합니다. 무인증 `/api/nif/uid`는 401이어야 합니다. 5000은 게이트웨이이며 5001/5002/51231/51233은 루프백이어야 합니다. 위 `curl -k`는 로봇 내부 readiness 검사에만 사용하며 PC 등록이나 브라우저의 인증서 검증을 생략하는 설정이 아닙니다.

Expect gateway version 1.5.1, NIF auth mode and the v2 enrollment capability. The unauthenticated API must return 401; protected backend listeners must be loopback. `curl -k` here is only a local readiness probe, not a PC/browser trust policy.

`host-guard status/survey`와 별도 LAN 검사를 통해 포트·DDS 우회 경계도 확인합니다. 방화벽은 재부팅 시 저장된 규칙을 적용하지만, 실제 재부팅 후 검증 여부는 별도로 기록합니다. 등록 파일과 인증 설정만으로 전체 네트워크 차단을 완료했다고 판단하지 않습니다.

## 기기 관리

로봇 SSH의 운영 `rgt` 계정에서 실행합니다. 공용 발급 비밀번호의 현재 정책은 `0000`이며, 아래 `issue`는 마스킹된 프롬프트로 입력받습니다. 이 공용 값은 개인별 관리자 신원 확인을 제공하지 않습니다. 비밀번호·코드·개인키·토큰을 명령 인수나 로그에 저장하지 않습니다.

Use the robot's operator `rgt` account over SSH. The configured shared issuance password is `0000`; `issue` reads it using a masked prompt. It does not provide per-person administrator identity. Do not put credentials in command arguments or logs.

```bash
rgt-nif-auth --help
rgt-nif-auth status

# 기본 read,package 코드 발급 / default permissions
rgt-nif-auth issue

# Vizanti/주행이 필요한 승인된 장비에만 / only explicitly authorized UI/drive devices
rgt-nif-auth issue --perms ui,read,drive,package

# 발급 응답의 generation_id로 해당 세대만 취소 / cancel that issuance generation
rgt-nif-auth cancel GENERATION_ID

rgt-nif-auth devices list
rgt-nif-auth devices revoke DEVICE_ID
```

`GENERATION_ID`와 `DEVICE_ID`는 실제 응답/목록의 값으로 바꿉니다. 코드 발급 응답은 8자리 코드·발급/만료 시각·발급 세대를 포함하며 운영 터미널에서만 확인합니다. 발급 파일은 `/run/rgt-network-iface/private/access-code.json`입니다. CLI는 NIF의 로컬 권위에 요청하며 이 파일을 사용자가 직접 고치는 절차가 아닙니다. 자동화의 `--password-stdin`은 신뢰한 로컬 입력 스트림용이며 기본 대화형 예시는 위 `issue`를 사용합니다.

Replace the ID placeholders with actual response/list values. The issuance reply includes code, issuance/expiry times and generation; inspect it only in the operator terminal. The daemon writes `/run/rgt-network-iface/private/access-code.json`; do not manually edit it. `--password-stdin` is available for a trusted local input stream; the examples use the interactive masked prompt.

NIF 로컬 관리 소켓은 허용된 운영 계정만 사용할 수 있습니다. SSH 셸이 없는 사용자는 네트워크 API로 등록 목록을 지우거나 새 코드를 발급할 수 없습니다. 기본 로봇 배포에서는 NIF와 게이트웨이가 `rgt` 계정으로 실행됩니다. 같은 UID로 임의 프로그램을 실행할 수 있는 사람까지 격리하는 설계는 아니며, 그러한 격리는 별도 서비스 계정/OS 권한 분리가 필요합니다. 코드·개인키·토큰·비밀번호를 로그에 출력하지 마세요.

## 테스트

```bash
python3 vizanti_server/tests/gateway_nif_auth_test.py
python3 vizanti_server/tests/gateway_enrollment_tls_test.py
python3 vizanti_server/tests/gateway_admission_test.py
# 기존 프로토콜/프록시 회귀 시험은 테스트 내부에서 legacy 모드를 명시합니다.
python3 vizanti_server/tests/gateway_selftest.py --tls
python3 vizanti_server/tests/gateway_api_test.py --tls
# 테스트 환경 websockets 15.0.1로 검증 / validated with test-only websockets 15.0.1
python3 vizanti_server/tests/gateway_ws_e2e.py
```

새 경계 시험은 실제 Unix 소켓과 TCP 백엔드를 사용하여 UID 검증, NIF 장애 시 503, 기존 로컬 등록/토큰의 우회 차단, 발급 요청의 키 소유 증명 전달, SSO의 NIF 세션 결합, 재시작/폐기 시 연결 종료, 백엔드 Authorization 전달을 확인합니다. 실제 NIF/로봇 연동 시험은 별도 배포 검증 기록을 참조합니다.

TLS 등록 경계 시험은 실제 TLS 1.3의 양측 exporter 일치, 같은 인증서의 별도 TLS 연결 분리, JSON의 가짜 binding 무시, 순서 제한, business route 혼입 차단, 중복 Content-Length 및 TLS 1.2 등록 거부를 확인합니다. PAKE 엔진과 실제 클라이언트의 통합 검증은 별도 시험으로 수행합니다.

admission 시험은 16KiB/16KiB+1 분할 경계, Host·버전·framing의 공통 거부, 정상 목록 헤더/WebSocket, 대기 중 취소·시간 초과와 늦은 transport 연결의 자원 회수를 검사합니다. 실제 TLS 시험은 대기 연결 만료 후 정상 등록 복구와 429/503 재시도 안내도 검사합니다. 모두 로컬 fixture이며 운영 로봇에 장애·부하 시험을 보내지 않습니다.

These commands run local fixtures, including simulated disruption/capacity cases. They do not demonstrate actual Windows GUI/DPAPI or a robot reboot. Production acceptance is a separate normal-function check: explicit test enrollment, saved-key login, read-only APIs, revocation and unauthenticated denial, followed by revoking only the test identities. Record its execution environment and results separately from isolated regression counts.
