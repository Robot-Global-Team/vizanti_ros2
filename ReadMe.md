# <img src="vizanti_server/public/assets/icon/512.png" alt="Vizanti" width="50" height="50"/> Vizanti — RGT secured robot UI

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.png)](https://opensource.org/licenses/BSD-3-Clause)

Vizanti는 ROS 로봇의 지도·상태를 표시하고 미션과 주행을 조작하는 웹 UI입니다. 이 브랜치는 **network-iface 인증 권위 + HTTPS 게이트웨이 + 루프백 백엔드**로 구성됩니다. 로봇 설치와 발급 명령은 [보안 게이트웨이 설치·운영 문서](vizanti_server/deploy/README.ko.md)를 따릅니다.

Vizanti provides web-based ROS visualization and mission/drive control. This branch uses a **network-iface authentication authority, HTTPS gateway and loopback backends**. Follow the [gateway installation and operations guide](vizanti_server/deploy/README.ko.md) for robot deployment and code issuance.

<img src="vizanti_server/public/assets/icon/preview.jpg" alt="Vizanti visualization interface"/>

## 현재 구성 / Current architecture

```text
PC: Python/WPF package editor or Windows RCS
  └─ HTTPS :5000 — Vizanti gateway
       ├─ IP + 8-digit code → TLS 1.3 PAKE enrollment
       ├─ saved Ed25519 key → challenge → API/UI token
       │    └─ /run/rgt-network-iface/gateway.sock (UID checked)
       │         └─ ~/.ros/.setting/devices.json + nif-auth-state.json
       ├─ /api/nif/* → 127.0.0.1:51231 (NIF REST)
       ├─ /api/pkg/* → 127.0.0.1:51233 (package HTTP)
       └─ authorized UI / WebSocket → 127.0.0.1:5002 / :5001

Kernel: vizanti_guard + host guard enforce
NIF binding: nif.mode=lock
SSH :22: separate operator administration
```

| 구성 / Component | 현재 역할 / Role |
|---|---|
| `vizanti_server` | 웹 자산·ROS 연동·TLS 게이트웨이·배포 도구 / Web assets, ROS integration, TLS gateway and deployment tools |
| [`network-iface`](https://github.com/Robot-Global-Team/network-iface) | 코드·등록·권한·서명·토큰의 단일 권위 / Single authority for codes, registrations, permissions, signatures and tokens |
| `vizanti_msgs`, `vizanti_cpp`, `vizanti_demos` | ROS 메시지·보조 노드·예제 / ROS messages, supporting nodes and examples |

## 등록과 접속 / Enrollment and access

- 운영자가 로봇 SSH 터미널에서 `rgt-nif-auth issue`로 공용 발급 비밀번호를 입력하면 **8자리 접속 코드**가 발급됩니다. **발급 후 60초, 최초 등록 성공 1회**만 유효합니다. 로봇 GUI의 발급 버튼과 코드 표시 화면은 구현되어 있지 않습니다.
- PC 앱은 **로봇 IP와 코드**로 `spake2-tls-exporter-v2` 등록을 수행합니다. 사용자가 인증서 지문을 입력하지 않습니다. 앱은 PAKE 상호 확인과 실제 TLS exporter를 검증한 뒤 인증서 pin·기기 키를 저장합니다.
- 등록은 로봇·PC·서비스 재시작 후에도 유지됩니다. 저장한 개인키로 코드 없이 재인증하며 운영자가 해당 기기를 폐기하면 접근이 거절됩니다. API 토큰 기본 15분·UI 세션 기본 2시간은 영구 등록의 만료 시간이 아닙니다.
- 기본 권한은 `read,package`입니다. Vizanti 웹 UI에는 명시적인 `ui` 권한이 필요합니다. `ui`는 rosbridge를 통한 주행 등 광범위 제어를 허용하며 읽기 전용 권한이 아닙니다. 허용된 주행 API에는 `drive` 권한이 필요합니다.
- 외부 진입점은 **`https://<robot-ip>:5000`**입니다. 미인증 브라우저의 보호 경로는 401로 거절됩니다. 허가된 앱이 받은 일회용 SSO 링크로 UI를 엽니다. 외부 브라우저의 인증서 신뢰는 앱의 pin과 별도로 구성해야 합니다.

Operators issue an eight-digit code using `rgt-nif-auth issue` over robot SSH. Codes expire after 60 seconds and permit one successful enrollment. Apps enroll with IP and code using TLS-bound PAKE without manual fingerprint entry; saved keys reconnect until revocation. Default `read,package` does not grant Vizanti `ui` or API `drive` access. Use **HTTPS port 5000** and an authorized app's single-use SSO link for the UI. Browser trust is separate from the app's pin. Robot-GUI issuance/display is not implemented.

발급·복구·폐기와 저장 경로 / Issuance, recovery, revocation and storage: [운영 문서](vizanti_server/deploy/README.ko.md#등록과-사용).

## 버전과 빌드 / Versions and build

**`vizanti_server/package.xml`과 게이트웨이 `VERSION`은 모두 `1.5.1`입니다.** 두 값은 함께 변경하며 전체 로봇 SW 릴리스와 다른 ROS 패키지의 버전은 별도로 관리합니다. CMake configure와 정식 설치기가 불일치를 거절합니다. 설치된 XML·CMake 메타데이터·실행 중 `/gw/info`도 같은 버전이어야 합니다.

**The `vizanti_server` package and gateway versions are both `1.5.1`.** Update them together. CMake configuration and the regular installer reject a mismatch. Installed XML/CMake metadata and running `/gw/info` must agree; the overall robot software release is managed separately.

현재 로봇 통합 기준은 ROS 2 Jazzy / Ubuntu 24.04입니다. 의존성을 준비한 작업공간에서 빌드합니다.

The current robot integration targets ROS 2 Jazzy on Ubuntu 24.04. Build in a workspace with the required dependencies:

```bash
# 작업공간 루트 / workspace root
source /opt/ros/jazzy/setup.bash
colcon build --packages-up-to vizanti_server
```

운영 배포에는 NIF native 엔진·인증 서비스·게이트웨이·방화벽과 루프백 내비게이션 launch가 함께 필요합니다. **인증서 준비 → NIF `--start` 설치 → 게이트웨이 설치** 순서는 [상세 설치 절차](vizanti_server/deploy/README.ko.md#로봇-설치)를 따릅니다. 로봇 bringup은 Flask `127.0.0.1:5002`와 rosbridge `127.0.0.1:5001`을 실행하며, 인증·게이트웨이는 독립 systemd 서비스로 실행합니다.

Production deployment requires the NIF native engine, authority, gateway, firewall and loopback navigation launch. Follow the guide's **certificate preparation → NIF `--start` installation → gateway installation** sequence. Robot bringup runs loopback Flask/rosbridge; the authority and gateway run as independent systemd services.

## 가용성 경계 / Availability boundaries

- TLS 수락부터 슬롯 대기·핸드셰이크까지 총 5초, HTTP 헤더 2초·16KiB 상한을 적용합니다. 코드 만료와 업무 업로드 제한은 별도입니다.
- 실제 소켓 IP로 진입 자원을 제한하며 JSON의 IP 주장이나 `X-Forwarded-For`를 신뢰하지 않습니다. 권위 장애는 오류로 닫으며 무인증 모드로 전환하지 않습니다.
- 공개 로그인 실패가 정상 기기 전체의 장기 잠금을 유발하지 않도록 분리합니다. 새 등록의 **로봇 전체 5회/600초 영구 선차감**은 유지합니다. 접속원별 제한은 병렬 선점 완화이며 공용 Wi-Fi의 순차·다중 주소 등록 방해를 완전히 제거하지 않습니다.
- `enforce/lock`은 방화벽·바인딩 정책입니다. SSH, 같은 OS 계정의 로컬 프로세스와 브라우저 인증서 신뢰는 별도 경계입니다.

TLS admission has a five-second total deadline; HTTP heads have a two-second/16KiB bound. Actual socket addresses drive admission limits; authority failures remain closed. Enrollment still durably spends a **robot-wide five attempts per 600 seconds**. Peer limits mitigate parallel monopolization but do not eliminate sequential/distributed enrollment denial on shared Wi-Fi. SSH, same-user local processes and browser certificate trust have separate boundaries.

## 검증과 UI 기능 / Validation and UI features

[시험 절차](vizanti_server/deploy/README.ko.md#테스트)는 로봇을 사용하지 않는 로컬 TLS·Unix 소켓·API·WebSocket fixture를 구분합니다. 로봇 정상 검증은 등록·키 재인증·읽기 API·폐기·무인증 거절을 확인합니다. 운영 로봇에 장애·부하 fixture를 실행하지 않습니다. 실제 Windows GUI·DPAPI와 로봇 재부팅의 실행 여부는 배포 검증 보고에서 별도로 확인합니다.

The [test instructions](vizanti_server/deploy/README.ko.md#테스트) cover isolated local TLS, Unix-socket, API and WebSocket fixtures. Robot acceptance uses normal enrollment, key login, read APIs, revocation and unauthenticated denial. Do not run disruption/load fixtures against production. Actual Windows GUI/DPAPI and reboot execution require separate evidence.

일반 지도·위젯·레이아웃 사용법은 [Vizanti 사용자 문서](https://moffkalast.github.io/vizanti_docs)를 참조합니다. 이 브랜치는 Compressed Image 위젯을 레이아웃 저장·가져오기에서 제외하며 다른 위젯과 설정은 유지합니다.

See the [Vizanti user documentation](https://moffkalast.github.io/vizanti_docs) for map/widget/layout usage. The Compressed Image widget is excluded when layouts are saved/imported; other widgets and settings are preserved.

기여 안내 / Contributing: [Contributing.md](Contributing.md).
