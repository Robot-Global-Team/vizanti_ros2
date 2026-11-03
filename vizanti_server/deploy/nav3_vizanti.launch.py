"""rgt_nav3_launch/launch/vizanti.launch.py — 3.4.0 교체본 (A1).

로봇 bringup(rgt_hard_bringup2/launch/hardware/hardware_sensors.launch.py) 은 vizanti_server 패키지의
launch 가 아니라 **이 파일**을 include 한다. 3.3.0 까지는 노드 5개를 여기서 복제해 flask *:5000(전체 인터페이스) /
rosbridge "":5001 로 직접 띄웠기 때문에, vizanti_server 쪽 루프백 격리가 로봇에는 적용되지 않았다.

이 교체본은 vizanti_server/launch/vizanti_server.launch.py 를 include 만 하므로 바인드 주소·포트의
진실 소스가 한 곳(vizanti_server)으로 통일된다:
  flask      127.0.0.1:5002
  rosbridge  127.0.0.1:5001   (탑재 GUI useRosbridge.ts 의 ws://localhost:5001 계약 유지)
  브라우저   port_public 5000 (vizanti_gateway)

설치: 이 파일을 rgt_navigation3/rgt_nav3_launch/launch/vizanti.launch.py 로 복사 (파일명·위치 유지 →
hardware_sensors.launch.py 무수정). 3.4.0 릴리스 번들에 rgt_navigation3 가 반드시 포함돼야 한다.
"""

import os

import launch
from ament_index_python.packages import get_package_share_directory
from launch.actions import IncludeLaunchDescription
from launch.launch_description_sources import PythonLaunchDescriptionSource


def generate_launch_description():
    home_dir = os.environ["HOME"]
    vizanti_config_path = os.path.join(home_dir, ".ros", ".setting", "vizanti")
    namespace = launch.substitutions.LaunchConfiguration("namespace", default="")

    vizanti = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(
                get_package_share_directory("vizanti_server"),
                "launch",
                "vizanti_server.launch.py",
            )
        ),
        launch_arguments={
            "default_widget_config": [vizanti_config_path + "/nav_vizanti_", namespace, ".json"],
            "flask_debug": "false",
            # 바인드 주소/포트는 vizanti_server.launch.py 기본값을 그대로 사용 (여기서 덮어쓰지 말 것)
        }.items(),
    )

    return launch.LaunchDescription([vizanti])


if __name__ == "__main__":
    launch.main()
