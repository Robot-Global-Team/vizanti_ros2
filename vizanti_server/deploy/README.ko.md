# Vizanti gateway 1.5.0 — 접속 코드 PAKE 등록 / NIF device authority

기본 인증 방식은 `nif-device-v1`입니다. network-iface 인증 서비스가 등록 기기, 코드, 서명 챌린지와 세션을 관리합니다. 게이트웨이의 기존 `clients.json`/`pairing_code`는 읽지 않으며 자동으로 가져오지도 않습니다. 기존 방식은 개발/호환 시험에서 `--auth-mode legacy`를 명시한 경우에만 사용합니다. 이전 동작의 기록은 [README.legacy.ko.md](README.legacy.ko.md)이며 신규 설치 절차로 사용하지 마세요.

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
- 기기 삭제, 토큰 만료, NIF 재시작/장애 시 새 요청은 인증에 실패합니다. 활성 HTTP/WebSocket/API 연결은 1초 주기 배치 확인과 2초 RPC 제한으로 보통 3초 이내, 늦어도 5초 이내에 끊습니다. NIF가 응답하지 않으면 보호 API는 503으로 종료하며 기존 인증으로 전환하지 않습니다.
- 정적 UI HTTP는 `GET`/`HEAD` 한 건마다 인증하고 `Connection: close`로 중계합니다. 요청 본문, Transfer-Encoding 및 파이프라인 후속 요청을 백엔드로 전달하지 않습니다. WebSocket만 양방향 중계를 유지합니다.
- `/gw/info`는 `auth_mode=nif-device-v1`을 유지하고 TLS backend와 NIF native 엔진이 준비됐을 때만 `enrollment_protocols=["spake2-tls-exporter-v2"]`를 광고합니다. 미준비 상태에서 신규 등록은 실패하며 기존 로그인은 유지됩니다. 등록/로그인 경로의 HTTP 접속 가능 여부가 보호 기능 사용 권한을 뜻하지 않습니다.

## 로봇 설치

새 `network-iface`와 native `rgt_pake` 라이브러리, `vizanti_server`, `python3-openssl`, 3.4.0 내비게이션 launch(Flask :5002/rosbridge :5001 루프백)가 함께 필요합니다. NIF REST/package 서버도 신규 인증 미들웨어가 적용된 버전을 배포해야 합니다. installer는 서비스 변경 전에 pyOpenSSL exporter API를 검사하고, 필요하면 Ubuntu `python3-openssl` 설치를 시도한 뒤 재검사합니다. 오프라인 설치는 의존성을 먼저 준비합니다.

1. network-iface의 `deploy/install_auth.sh`로 `/usr/local/bin/rgt-nif-auth`, `network-iface-auth.service`를 설치합니다. 해당 서비스의 `RuntimeDirectory`가 `/run/rgt-network-iface`를 만들고 소켓을 준비합니다. 등록 파일은 실행 계정 기준 `~/.ros/.setting/devices.json`에 남습니다.
2. `vizanti_server` 배포 후 `sudo bash install_vizanti_gateway.sh`를 실행합니다. 로봇별 TLS 인증서를 `~rgt/.rgt_data/vizanti_gateway/tls_cert.pem`에 만들고 게이트웨이를 시작합니다. NIF와 게이트웨이가 같은 인증서 지문을 사용하는지 확인합니다.
3. 첫 설치의 기본값은 **`nif.mode=lock` + host guard `MODE=enforce`**입니다. 기존 설정은 보존되므로 기존 로봇 업그레이드 시 아래 명령을 별도로 실행해야 합니다. host guard 적용 실패 시 설치는 성공으로 종료하지 않습니다.

```bash
sudo bash install_vizanti_gateway.sh nif-lock
sudo bash install_vizanti_gateway.sh host-guard enforce
# network-iface의 HTTP 바인드 변경은 노드/ROS 스택 재시작 후 적용됩니다.
sudo systemctl status network-iface-auth vizanti-gateway
curl -ks https://127.0.0.1:5000/gw/info   # 검사만: version=1.5.0 / enrollment_protocols 확인
openssl x509 -in /home/rgt/.rgt_data/vizanti_gateway/tls_cert.pem -noout -fingerprint -sha256
```

전체 host guard를 enforce로 바꾸기 전에 로봇의 정당한 하드웨어 네트워크/운영 서비스 예외를 확인합니다. SSH는 별도 관리 경로입니다. `host-guard status/survey`와 LAN 포트 검사를 수행하고, 재부팅 후 51231/51233/5001–5003 및 외부 DDS가 우회 경로로 남지 않는지 검사합니다. 등록 파일만 설정해도 네트워크 차단이 완료되는 것은 아닙니다.

## 기기 관리

```bash
rgt-nif-auth --help
rgt-nif-auth devices list
rgt-nif-auth devices revoke DEVICE_ID
```

NIF 로컬 관리 소켓은 허용된 운영 계정만 사용할 수 있습니다. SSH 셸이 없는 사용자는 네트워크 API로 등록 목록을 지우거나 새 코드를 발급할 수 없습니다. 기본 로봇 배포에서는 NIF와 게이트웨이가 `rgt` 계정으로 실행됩니다. 같은 UID로 임의 프로그램을 실행할 수 있는 사람까지 격리하는 설계는 아니며, 그러한 격리는 별도 서비스 계정/OS 권한 분리가 필요합니다. 코드·개인키·토큰·비밀번호를 로그에 출력하지 마세요.

## 테스트

```bash
python3 vizanti_server/tests/gateway_nif_auth_test.py
python3 vizanti_server/tests/gateway_enrollment_tls_test.py
# 기존 프로토콜/프록시 회귀 시험은 테스트 내부에서 legacy 모드를 명시합니다.
python3 vizanti_server/tests/gateway_selftest.py --tls
python3 vizanti_server/tests/gateway_api_test.py --tls
```

새 경계 시험은 실제 Unix 소켓과 TCP 백엔드를 사용하여 UID 검증, NIF 장애 시 503, 기존 로컬 등록/토큰의 우회 차단, 발급 요청의 키 소유 증명 전달, SSO의 NIF 세션 결합, 재시작/폐기 시 연결 종료, 백엔드 Authorization 전달을 확인합니다. 실제 NIF/로봇 연동 시험은 별도 배포 검증 기록을 참조합니다.

TLS 등록 경계 시험은 실제 TLS 1.3의 양측 exporter 일치, 같은 인증서의 별도 TLS 연결 분리, JSON의 가짜 binding 무시, 순서 제한, business route 혼입 차단, 중복 Content-Length 및 TLS 1.2 등록 거부를 확인합니다. PAKE 엔진과 실제 클라이언트의 통합 검증은 별도 시험으로 수행합니다.
