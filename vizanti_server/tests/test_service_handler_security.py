#!/usr/bin/env python3
"""scripts/service_handler.py (ROS 2) 보안 회귀 테스트. ROS 불필요: rclpy 등은 sys.modules 스텁으로 대체한다.

defect_review_confirmed.md 항목별 검증:
  [14] node/start: 'ros2 launch ... launch-prefix:=<바이너리>' 로 허용목록 우회 -> 거부.
       launch 인자 이름에는 '-' 불가 (launch-prefix, launch-prefix-filter 가 함께 막힘).
  [15] node/start: '__' 로 시작하는 예약 키, launch_prefix 계열 키(대소문자, -/_ 변형) -> 거부.
       정상 입력(use_sim_time:=true, map:=/home/rgt/maps/x.yaml)은 그대로 통과.
  [16] node/kill: 부분문자열 과매칭 제거. argv 의 노드 이름/네임스페이스 remap 을 rcl 처럼 읽어(__name 은 __node,
       같은 종류는 첫 규칙 우선, 값을 받는 플래그의 값은 건너뜀, 규칙이 없으면 실행 파일 이름) 정확 일치. 노드 접두
       규칙이나 --ros-args 밖의 (deprecated) 규칙에 이름이 달린 프로세스는 후보에서 제외. 2건 이상이면 거부,
       0건이면 success=False, SIGTERM 후 유예 시간이 지나도 같은 프로세스(pid + 시작 시각)가 살아 있을 때만 SIGKILL.
       node/start 는 'ros2 run' 에 --ros-args 와 프로세스마다 다른 enclave 를 붙인다(SROS2 를 켜면 enclave 는 뺀다).
       node/kill 은 ROS 그래프가 그 enclave 에 적은 노드 이름으로 그 프로세스를 고르므로, 실행 파일 이름과 노드
       이름이 다른 UI 노드(turtlesim_node -> /turtlesim)도 끌 수 있다. 다른 프로세스는 계속 argv 로만 판단한다.
  [18] bag/setup: 토픽 자리의 옵션 주입(-a, --regex, -o ...) 거부, -o 는 홈 디렉터리 아래 새 경로만.
안전: 실제 프로세스에 시그널을 보내지 않는다. os.kill/os.killpg 는 모든 테스트에서 차단(호출되면 실패)하고,
/proc 은 tmp_path 아래 가짜 디렉터리를 쓰며, 가짜 pid 는 pid_max(2^22)보다 커서 실제로 존재할 수 없다.
subprocess 는 argv 만 기록하는 가짜로 바꾼다.

실행: PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_service_handler_security.py
"""

import importlib.util
import os
import re
import shutil
import signal
import sys
import types
from unittest import mock

import pytest

# 아래 service_handler.py import 의 pyc 만 막는다. 이 테스트 파일의 pyc 는 이 줄보다 먼저 pytest 가 쓰므로,
# 저장소에 __pycache__ 가 생기지 않으려면 실행 줄의 PYTHONDONTWRITEBYTECODE=1 이 필요하다.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, '..', 'scripts', 'service_handler.py')
PACKAGES = ['demo_nodes_cpp', 'nav2_bringup', 'turtlesim', 'vizanti_server']
PID0 = 5000001  # > pid_max(4194304): 실제 프로세스와 절대 겹치지 않는다


# ---------------------------------------------------------------------------------------------
# ROS 스텁과 모듈 로드
# ---------------------------------------------------------------------------------------------

class _Bag(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Srv(object):
    Request = _Bag
    Response = _Bag


class _Param(object):
    def __init__(self, value):
        self.value = value


class _Logger(object):
    def info(self, *args, **kw):
        pass

    error = warn = warning = debug = info


class _Node(object):
    def __init__(self, name, *args, **kw):
        self.params = {}
        self.descriptors = {}
        self.graph = []  # ROS 그래프의 (name, namespace, enclave): 테스트가 정한다

    def get_node_names_and_namespaces_with_enclaves(self):
        return list(self.graph)

    def declare_parameter(self, name, value=None, descriptor=None, *args, **kw):
        self.params[name] = value
        self.descriptors[name] = descriptor

    def get_parameter(self, name):
        return _Param(self.params[name])

    def create_service(self, *args, **kw):
        return object()

    def get_logger(self):
        return _Logger()


def _module(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    return mod


def _load_service_handler():
    srv_names = ('GetNodeParameters', 'SetNodeParameter', 'LoadMap', 'SaveMap', 'RecordRosbag',
                 'ManageNode', 'ListPackages', 'ListExecutables', 'ListLifecycles')
    executors = _module('rclpy.executors', MultiThreadedExecutor=object, ExternalShutdownException=Exception)
    stubs = {
        'rclpy': _module('rclpy', init=lambda *a, **k: None, shutdown=lambda *a, **k: None, executors=executors),
        'rclpy.node': _module('rclpy.node', Node=_Node),
        'rclpy.executors': executors,
        'rclpy.callback_groups': _module('rclpy.callback_groups', ReentrantCallbackGroup=object),
        'rclpy.parameter': _module('rclpy.parameter', Parameter=object),
        'rcl_interfaces': _module('rcl_interfaces'),
        'rcl_interfaces.msg': _module('rcl_interfaces.msg', ParameterDescriptor=_Bag),
        'ros2lifecycle': _module('ros2lifecycle'),
        'ros2lifecycle.api': _module('ros2lifecycle.api', get_node_names=lambda **k: []),
        'ros2pkg': _module('ros2pkg'),
        'ros2pkg.api': _module('ros2pkg.api', get_package_names=lambda: list(PACKAGES),
                               get_prefix_path=lambda pkg: '/opt/ros/jazzy'),
        'rqt_reconfigure_param_api': _module('rqt_reconfigure_param_api', create_param_client=None),
        'std_srvs': _module('std_srvs'),
        'std_srvs.srv': _module('std_srvs.srv', Trigger=type('Trigger', (_Srv,), {})),
        'vizanti_msgs': _module('vizanti_msgs'),
        'vizanti_msgs.srv': _module('vizanti_msgs.srv', **dict((n, type(n, (_Srv,), {})) for n in srv_names)),
        'lifecycle_msgs': _module('lifecycle_msgs'),
        'lifecycle_msgs.srv': _module('lifecycle_msgs.srv', GetState=_Srv),
        'lifecycle_msgs.msg': _module('lifecycle_msgs.msg', State=object),
    }
    spec = importlib.util.spec_from_file_location('service_handler_340_under_test', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, stubs):
        spec.loader.exec_module(mod)
    return mod


sh = _load_service_handler()


# ---------------------------------------------------------------------------------------------
# 공용 픽스처
# ---------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_real_signals(monkeypatch):
    """어떤 경로로든 실제 os.kill 이 불리면 테스트가 실패한다."""
    def forbidden(*args):
        raise AssertionError('real signal attempted: %r' % (args,))
    monkeypatch.setattr(os, 'kill', forbidden)
    monkeypatch.setattr(os, 'killpg', forbidden)


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.delenv('ROS_SECURITY_ENABLE', raising=False)  # SROS2 를 켠 셸에서 돌려도 같은 결과
    return sh.ServiceHandler(group=None)


class FakeSubprocess(object):
    """subprocess 대역: 아무것도 실행하지 않고 argv 만 기록한다."""
    PIPE = -1
    STDOUT = -2
    DEVNULL = -3

    def __init__(self):
        self.calls = []
        self.procs = []
        outer = self

        class Popen(object):
            def __init__(self, argv, **kw):
                outer.calls.append(list(argv))
                outer.procs.append(self)
                self.pid = PID0 + 999
                self.terminated = False

            def terminate(self):
                self.terminated = True

            def wait(self, *args):
                return 0

            def poll(self):
                return None

        self.Popen = Popen

    def call(self, argv, **kw):
        raise AssertionError('unexpected subprocess.call %r' % (argv,))

    check_output = call


@pytest.fixture
def fake_subprocess(monkeypatch):
    fake = FakeSubprocess()
    monkeypatch.setattr(sh, 'subprocess', fake)
    return fake


class FakeProc(object):
    """tmp_path 아래 가짜 /proc: <pid>/cmdline (NUL 구분) 과 <pid>/stat (22번째 필드 = 시작 시각)."""

    def __init__(self, root):
        self.root = str(root)
        os.makedirs(self.root)
        for name in ('self', 'net', 'sys'):  # 숫자가 아닌 항목은 건너뛰어야 한다
            os.makedirs(os.path.join(self.root, name))

    def add(self, pid, argv, state='S', start=1000, comm='node'):
        os.makedirs(os.path.join(self.root, str(pid)))
        with open(os.path.join(self.root, str(pid), 'cmdline'), 'wb') as f:
            f.write(b''.join(a.encode('utf-8') + b'\0' for a in argv))
        self.set_stat(pid, state, start, comm)

    def set_stat(self, pid, state='S', start=1000, comm='node'):
        fields = [state] + ['0'] * 18 + [str(start)] + ['0'] * 10
        with open(os.path.join(self.root, str(pid), 'stat'), 'w') as f:
            f.write('%d (%s) %s\n' % (pid, comm, ' '.join(fields)))

    def remove(self, pid):
        shutil.rmtree(os.path.join(self.root, str(pid)))


def launch_argv(exe, name=None, ns=None):
    """launch_ros Node 가 만드는 형식: exe --ros-args [-r __node:=] --params-file .. -r remap [-r __ns:=]."""
    argv = [exe, '--ros-args']
    if name:
        argv += ['-r', '__node:=' + name]
    argv += ['--params-file', '/tmp/launch_params_x1y2', '-r', '/tf:=tf']
    if ns:
        argv += ['-r', '__ns:=' + ns]
    return argv


LIB = '/opt/ros/jazzy/lib/'
ROBOT = {
    # pid 오프셋: argv
    1: launch_argv(LIB + 'nav2_collision_monitor/collision_monitor', 'collision_monitor', '/'),
    2: launch_argv(LIB + 'nav2_lifecycle_manager/lifecycle_manager', 'lifecycle_manager_safety'),
    3: launch_argv(LIB + 'nav2_lifecycle_manager/lifecycle_manager', 'lifecycle_manager_navigation'),
    4: launch_argv(LIB + 'nav2_amcl/amcl', 'amcl'),
    5: launch_argv(LIB + 'nav2_map_server/map_server', 'map_server_localization'),
    6: ['/usr/bin/python3', LIB + 'rosbridge_server/rosbridge_websocket', '--ros-args',
        '-r', '__node:=rosbridge_websocket'],
    7: [LIB + 'turtlesim/turtlesim_node', '--ros-args'],                       # remap 없음: 실행 파일 이름
    8: launch_argv(LIB + 'nav2_amcl/amcl', 'amcl', '/robot1'),                 # 같은 이름, 다른 네임스페이스
    9: ['/usr/bin/python3', '/opt/ros/jazzy/bin/ros2', 'run', 'demo_nodes_cpp', 'talker',
        '--ros-args', '-r', '__node:=talker_remapped'],                         # ros2 run CLI (부모)
    10: [LIB + 'demo_nodes_cpp/talker', '--ros-args', '-r', '__node:=talker_remapped'],  # 실제 노드 (자식)
    11: ['python3', LIB + 'my_pkg/my_py_node', '--ros-args'],                  # env python3 셔뱅 노드
    # rcl 해석 규칙 (Jazzy librcl 로 확인한 결과와 같아야 한다)
    12: [LIB + 'demo_nodes_cpp/talker', '--ros-args', '-r', '__name:=chatter_pub'],  # __name = __node
    13: [LIB + 'demo_nodes_cpp/listener', '--ros-args', '-r', '__node:=talker_a',   # launch_ros 순서: ros_arguments
         '--ros-args', '-r', '__node:=talker_b', '--params-file', '/tmp/launch_params_x1y2'],  # 가 Node(name=) 앞
    14: [LIB + 'demo_nodes_cpp/add_two_ints_server', '--ros-args', '-r', 'add_two_ints_server:__node:=prefixed'],
    15: [LIB + 'demo_nodes_cpp/listener_best_effort', '--ros-args', '-r', 'listener_best_effort:__ns:=/r2'],
    16: [LIB + 'demo_nodes_cpp/talker_loaned_message', '--ros-args', '--log-file-name', '-r', '-r', '__node:=loaned'],
    17: [LIB + 'x/decided_node', '--ros-args', '-r', '__node:=decided', '--', '__node:=later'],
    18: [LIB + 'x/prefix_after', '--ros-args', '-r', '__node:=first_wins', '-r', 'prefix_after:__node:=later'],
    19: ['__node:=argv0', '--ros-args', '-r', '__node:=later_rule'],              # exec -a: rcl 은 argv[0] 도 읽는다
    # ROS 2 노드가 아닌 것 / 대상이 아닌 것
    21: ['/usr/share/code/code', '--type=renderer', '--enable-crash-reporter'],  # 편집기
    22: ['bash'],
    23: ['/usr/bin/python3', '/home/rgt/editor.py', 'amcl', 'collision_monitor', '--ros-args-like'],
    24: [LIB + 'nav2_amcl/amcl'],                                               # --ros-args 없음
    25: ['/usr/bin/python3', '/opt/ros/jazzy/bin/ros2', 'launch', 'nav2_bringup', 'bringup_launch.py'],
    26: [LIB + 'x/fake_node', '__node:=fake_target', '--ros-args'],            # --ros-args 밖의 규칙
    27: [LIB + 'x/other_node', '--ros-args', '--', '-r', '__node:=after_dashdash'],  # '--' 뒤도 --ros-args 밖
}


@pytest.fixture
def robot(tmp_path, monkeypatch):
    proc = FakeProc(tmp_path / 'proc')
    for off, argv in sorted(ROBOT.items()):
        proc.add(PID0 + off, argv, comm='n%d' % off)
    proc.add(PID0 + 28, launch_argv(LIB + 'x/zombie', 'zombie_node'), state='Z')
    # 자기 자신은 절대 대상이 아니다
    proc.add(os.getpid(), launch_argv('/usr/bin/vizanti_service_handler', 'me'))
    monkeypatch.setattr(sh, '_PROC', proc.root)
    return proc


def pids(matches):
    return sorted(pid - PID0 for pid, _ in matches)


class Req(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Res(object):
    success = None
    message = None


# ---------------------------------------------------------------------------------------------
# [14] [15] node/start
# ---------------------------------------------------------------------------------------------

START_REJECT = [
    # [14] 재현 입력 (launch-prefix 계열)
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix:=/bin/sh',
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix:=rm',
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix-filter:=x launch-prefix:=/usr/bin/sudo',
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix:=/usr/bin/echo',
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix-filter:=x',
    'ros2 launch turtlesim multisim.launch.py launch-prefix:=/usr/bin/echo',
    'ros2 launch turtlesim multisim.launch.py launch-prefix:=id',
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix:=gdb -ex run',
    'ros2 launch vizanti_server vizanti_server.launch.py --prefix',
    'ros2 launch vizanti_server vizanti_server.launch.py launch-prefix-filter:=.*',
    # 대소문자, -/_ 변형
    'ros2 launch vizanti_server vizanti_server.launch.py launch_prefix:=/bin/sh',
    'ros2 launch vizanti_server vizanti_server.launch.py LAUNCH-PREFIX:=/bin/sh',
    'ros2 launch vizanti_server vizanti_server.launch.py Launch_Prefix-Filter:=x',
    'ros2 launch vizanti_server vizanti_server.launch.py launch_prefix_filter:=x',
    # launch 인자 이름에 '-' 불가
    'ros2 launch vizanti_server vizanti_server.launch.py use-sim-time:=true',
    # [15] 예약 키 (ROS 2 에도 동일 적용)
    'ros2 launch vizanti_server vizanti_server.launch.py __node:=x',
    'ros2 launch vizanti_server vizanti_server.launch.py __ns:=/x',
    'ros2 run turtlesim turtlesim_node __node:=evil',
    'ros2 run turtlesim turtlesim_node __params:=/tmp/p.yaml',
    'ros2 run turtlesim turtlesim_node __log_level:=debug',
    'ros2 run turtlesim turtlesim_node __master:=http://10.0.0.5:11311',
    'ros2 run turtlesim turtlesim_node launch-prefix:=/bin/sh',
    'ros2 run turtlesim turtlesim_node LAUNCH_PREFIX:=/bin/sh',
    # 기존에도 막히던 것 (회귀 방지)
    'ros2 run turtlesim turtlesim_node --ros-args',
    'ros2 run turtlesim -h',
    'ros2 run turtlesim turtlesim_node a:=$(id)',
    'ros2 run turtlesim turtlesim_node a:=1;id',
    "ros2 run turtlesim turtlesim_node a:='x'",
    'ros2 run turtlesim turtlesim_node a:=`id`',
    'ros2 run turtlesim turtlesim_node a:=1|id',
    'ros2 run unknown_pkg x',
    'ros2 launch vizanti_server',
    'sh -c id',
    '',
]

START_ACCEPT = [
    'ros2 launch vizanti_server vizanti_server.launch.py use_sim_time:=true',
    'ros2 launch nav2_bringup bringup_launch.py map:=/home/rgt/maps/x.yaml use_sim_time:=true',
    'ros2 launch turtlesim multisim.launch.py',
    'ros2 run turtlesim turtlesim_node',
    'ros2 run demo_nodes_cpp talker',
    'ros2 run demo_nodes_cpp talker rate:=10',
]


@pytest.mark.parametrize('command', START_REJECT)
def test_start_command_rejects(handler, command):
    with pytest.raises(ValueError):
        handler.start_command(command)


@pytest.mark.parametrize('command', START_ACCEPT)
def test_start_command_accepts(handler, command):
    assert handler.start_command(command) == command.split()


def test_start_reason_names_the_rule(handler):
    with pytest.raises(ValueError, match='launch prefix'):
        handler.start_command('ros2 launch vizanti_server vizanti_server.launch.py launch-prefix:=/bin/sh')
    with pytest.raises(ValueError, match='reserved ROS argument'):
        handler.start_command('ros2 run turtlesim turtlesim_node __node:=evil')


def test_node_start_spawns_only_validated(handler, fake_subprocess):
    for command in START_REJECT:
        res = handler.node_start(Req(node=command), Res())
        assert res.success is False, command
    assert fake_subprocess.calls == []
    res = handler.node_start(Req(node='ros2 launch vizanti_server vizanti_server.launch.py use_sim_time:=true'), Res())
    assert res.success is True
    assert fake_subprocess.calls == [['ros2', 'launch', 'vizanti_server', 'vizanti_server.launch.py', 'use_sim_time:=true']]


def test_allowed_packages_parameter_is_read_only_and_enforced(handler):
    assert handler.descriptors['node_start_allowed_packages'].read_only is True
    handler.params['node_start_allowed_packages'] = 'turtlesim'
    assert handler.start_command('ros2 run turtlesim turtlesim_node')
    with pytest.raises(ValueError, match='node_start_allowed_packages'):
        handler.start_command('ros2 run demo_nodes_cpp talker')


# ---------------------------------------------------------------------------------------------
# [16] node/kill: 매칭
# ---------------------------------------------------------------------------------------------

def test_review_patterns_match_nothing(robot):
    # [16] 재현: 예전 코드에서 'ros', '--ros-args', 'args', '/opt' 는 ROS 노드 전부와 매칭됐다
    for pattern in ('ros', 'args', '/opt'):
        assert sh.ServiceHandler.find_ros_node_pids(pattern) == [], pattern
    with pytest.raises(ValueError):
        sh.ServiceHandler.find_ros_node_pids('--ros-args')


@pytest.mark.parametrize('node, expected', [
    ('/collision_monitor', [1]),
    ('/lifecycle_manager_safety', [2]),
    ('/lifecycle_manager_navigation', [3]),
    ('/amcl', [4]),                    # /robot1/amcl(8) 과 --ros-args 없는 amcl(24) 은 아니다
    ('amcl', [4]),                     # 선행 '/' 생략 = 루트 네임스페이스
    ('/robot1/amcl', [8]),
    ('/map_server_localization', [5]),
    ('/rosbridge_websocket', [6]),
    ('/turtlesim_node', [7]),          # remap 없는 노드: 실행 파일 이름 정확 일치
    ('/talker_remapped', [10]),        # ros2 run CLI(9)는 제외, 노드(10)만
    ('/my_py_node', [11]),             # python 노드: 스크립트 이름
    ('/lifecycle_manager', []),        # 실행 파일 이름이지만 둘 다 __node remap 이 있다
    ('/map_server', []),
    ('/robot1', []),
    ('/code', []),                     # 편집기: --ros-args 없음
    ('/bash', []),
    ('/editor', []),
    ('/collision', []),                # 부분 문자열은 매칭되지 않는다
    ('/chatter_pub', [12]),            # rcl lexer: __name 은 __node 와 같다
    ('/talker', []),                   # ... 그래서 12 는 /talker 가 아니다
    ('/talker_a', [13]),               # 같은 종류의 규칙은 첫 규칙이 이긴다
    ('/talker_b', []),
    ('/prefixed', []),                 # 노드 접두 규칙은 코드 안 노드 이름에 달렸다: argv 로 판단 불가, 제외
    ('/add_two_ints_server', []),
    ('/r2/listener_best_effort', []),
    ('/listener_best_effort', []),
    ('/loaned', [16]),                 # --log-file-name 의 값 '-r' 은 플래그가 아니다
    ('/talker_loaned_message', []),
    ('/decided', [17]),                # 이미 정해진 이름은 뒤의 규칙이 바꾸지 못한다
    ('/first_wins', [18]),
    ('/later_rule', []),               # argv[0] 의 규칙이 먼저다: 판단 불가, 제외
    ('/fake_target', []),              # rcl(Jazzy)은 --ros-args 밖의 규칙도 deprecated 구문으로 적용한다:
    ('/fake_node', []),                # 이런 규칙에 이름이 달린 프로세스는 판단 불가, 제외
    ('/after_dashdash', []),
    ('/other_node', []),
    ('/zombie_node', []),
    ('/me', []),                       # 자기 자신
])
def test_exact_matching(robot, node, expected):
    assert pids(sh.ServiceHandler.find_ros_node_pids(node)) == expected


@pytest.mark.parametrize('node', ['', '/', '//amcl', '/amcl/', '-a', '--ros-args', '/opt/*', 'a b',
                                  '/1abc', '/amcl;reboot', '$(id)', '/am-cl', '/amcl/../x', '~/amcl'])
def test_invalid_node_names(robot, node):
    with pytest.raises(ValueError):
        sh.ServiceHandler.find_ros_node_pids(node)


def test_start_time_comes_from_stat(robot):
    robot.set_stat(PID0 + 1, start=777, comm='weird (name) x')  # comm 안의 공백과 ')'
    assert sh.ServiceHandler.find_ros_node_pids('/collision_monitor') == [(PID0 + 1, b'777')]


# ---------------------------------------------------------------------------------------------
# [16] node/kill: 서비스 응답과 시그널 순서
# ---------------------------------------------------------------------------------------------

class KillRecorder(object):
    """os.kill 대역: 기록만 하고, 지정한 시그널을 받으면 가짜 /proc 에서 프로세스를 지운다."""

    def __init__(self, proc, exits_on=(signal.SIGTERM, signal.SIGKILL), error=None):
        self.proc, self.exits_on, self.error, self.sent = proc, exits_on, error, []

    def __call__(self, pid, sig):
        if self.error:
            raise self.error
        self.sent.append((pid - PID0, sig))
        if sig in self.exits_on:
            self.proc.remove(pid)


def test_node_kill_sigterm_only_when_node_exits(robot, handler, monkeypatch):
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    res = handler.node_kill(Req(node='/collision_monitor'), Res())
    assert res.success is True and 'SIGTERM' in res.message
    assert killer.sent == [(1, signal.SIGTERM)]


def test_node_kill_sigkill_after_grace(robot, handler, monkeypatch):
    killer = KillRecorder(robot, exits_on=(signal.SIGKILL,))  # SIGTERM 무시
    monkeypatch.setattr(os, 'kill', killer)
    monkeypatch.setattr(sh, '_KILL_GRACE', 0.25)
    res = handler.node_kill(Req(node='/amcl'), Res())
    assert res.success is True and 'SIGKILL' in res.message
    assert killer.sent == [(4, signal.SIGTERM), (4, signal.SIGKILL)]


@pytest.mark.parametrize('node', ['ros', '--ros-args', 'args', '/opt', '/nonexistent', '/code', ''])
def test_node_kill_nothing_matched_is_failure(robot, handler, monkeypatch, node):
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    res = handler.node_kill(Req(node=node), Res())
    assert res.success is False
    assert killer.sent == []


def test_node_kill_refuses_ambiguous(robot, handler, monkeypatch):
    robot.add(PID0 + 40, launch_argv(LIB + 'x/dup', 'dup'))
    robot.add(PID0 + 41, launch_argv(LIB + 'y/dup', 'dup', '/'))
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    res = handler.node_kill(Req(node='/dup'), Res())
    assert res.success is False and 'Not killed: 2 processes' in res.message
    assert killer.sent == []


def test_node_kill_permission_error_is_failure(robot, handler, monkeypatch):
    monkeypatch.setattr(os, 'kill', KillRecorder(robot, error=PermissionError('not permitted')))
    res = handler.node_kill(Req(node='/amcl'), Res())
    assert res.success is False and 'not permitted' in res.message


START_ENCLAVE_RE = re.compile(r'^/vizanti_node_start/n[0-9a-f]{16}\Z')


def ui_node(robot, handler, fake_subprocess, command, off, exe):
    """node_start 로 띄운 'ros2 run' 의 CLI(off) 와 노드(off + 1) 를 가짜 /proc 에 넣고, 붙은 enclave 를 돌려준다."""
    assert handler.node_start(Req(node=command), Res()).success is True
    argv = fake_subprocess.calls[-1]
    robot.add(PID0 + off, ['/usr/bin/python3', '/opt/ros/jazzy/bin/ros2'] + argv[1:])  # ros2 run CLI (부모)
    robot.add(PID0 + off + 1, [LIB + exe] + argv[4:])  # ros2run/api: cmd = [path] + argv (자식)
    return argv[-1]


def test_node_start_ros2_run_node_is_killable(robot, handler, fake_subprocess, monkeypatch):
    # nodemgr UI 는 인자 없는 'ros2 run' 을 보낸다. ros2 run 은 실행 파일 이름 뒤의 인자를 그대로 노드 argv 로
    # 넘기므로(ros2run/api: cmd = [path] + argv), node_start 가 붙인 --ros-args 로 그 노드가 kill 후보가 된다
    for command in ('ros2 run demo_nodes_cpp talker', 'ros2 run demo_nodes_cpp talker rate:=10'):
        assert handler.node_start(Req(node=command), Res()).success is True
    first, second = fake_subprocess.calls
    assert first[:-1] == ['ros2', 'run', 'demo_nodes_cpp', 'talker', '--ros-args', '--enclave']
    assert second[:-1] == ['ros2', 'run', 'demo_nodes_cpp', 'talker', 'rate:=10', '--ros-args', '--enclave']
    assert START_ENCLAVE_RE.match(first[-1]) and START_ENCLAVE_RE.match(second[-1])
    assert first[-1] != second[-1]  # 프로세스마다 다르다
    robot.add(PID0 + 50, ['/usr/bin/python3', '/opt/ros/jazzy/bin/ros2'] + first[1:])  # ros2 run CLI (부모)
    robot.add(PID0 + 51, [LIB + 'demo_nodes_cpp/talker'] + first[4:])                   # 노드 (자식)
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    res = handler.node_kill(Req(node='/talker'), Res())  # 그래프에 아직 없어도 argv(실행 파일 이름) 로 찾는다
    assert res.success is True and killer.sent == [(51, signal.SIGTERM)]


@pytest.mark.parametrize('security, enclave', [(None, True), ('false', True), ('true', False)])
def test_node_start_enclave_only_without_sros2(handler, fake_subprocess, monkeypatch, security, enclave):
    # SROS2(ROS_SECURITY_ENABLE=true, rcl 은 정확히 'true' 만 본다)에서는 enclave 가 keystore 항목을 고르므로 붙이지 않는다
    if security is not None:
        monkeypatch.setenv('ROS_SECURITY_ENABLE', security)
    assert handler.node_start(Req(node='ros2 run turtlesim turtlesim_node'), Res()).success is True
    argv = fake_subprocess.calls[-1]
    assert argv[:5] == ['ros2', 'run', 'turtlesim', 'turtlesim_node', '--ros-args']
    if enclave:
        assert argv[5] == '--enclave' and START_ENCLAVE_RE.match(argv[6]) and len(argv) == 7
    else:
        assert len(argv) == 5


def test_node_kill_ui_node_named_by_graph(robot, handler, fake_subprocess, monkeypatch):
    # turtlesim_node 가 띄우는 노드는 /turtlesim: argv 로는 알 수 없고, 그래프가 node_start 의 enclave 에 적은 이름으로 찾는다
    enclave = ui_node(robot, handler, fake_subprocess, 'ros2 run turtlesim turtlesim_node', 60,
                      'turtlesim/turtlesim_node')
    handler.graph = [('turtlesim', '/', enclave), ('amcl', '/', '/'), ('vizanti_service_handler', '/', '/')]
    started = handler.started_nodes()
    assert started == {enclave: {('/', 'turtlesim')}}

    def find(node, started=started):
        return pids(sh.ServiceHandler.find_ros_node_pids(node, started=started))
    assert find('/turtlesim') == [61]           # CLI(60) 는 같은 enclave 를 달고 있어도 제외
    assert find('/turtlesim_node') == [7]       # 61 은 그래프가 이름을 정했으므로 실행 파일 이름 추측을 쓰지 않는다
    assert find('/turtlesim', None) == []       # 그래프 정보가 없으면 예전처럼 argv 로만: 못 찾는다
    assert find('/turtlesim_node', None) == [7, 61]
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    res = handler.node_kill(Req(node='/turtlesim'), Res())
    assert res.success is True and killer.sent == [(61, signal.SIGTERM)]


def test_node_kill_graph_enclave_never_widens(robot, handler, fake_subprocess, monkeypatch):
    # 그래프는 DDS 로 누구나 광고할 수 있다. node_start 가 준 enclave 를 실제로 단 프로세스만, 그래프가 그 enclave 에
    # 적은 이름에 대해서만 후보가 된다. 다른 프로세스는 계속 argv 로 판단하고, 2건 이상이면 거부한다
    ts = ui_node(robot, handler, fake_subprocess, 'ros2 run turtlesim turtlesim_node', 60, 'turtlesim/turtlesim_node')
    t1 = ui_node(robot, handler, fake_subprocess, 'ros2 run demo_nodes_cpp talker', 70, 'demo_nodes_cpp/talker')
    t2 = ui_node(robot, handler, fake_subprocess, 'ros2 run demo_nodes_cpp talker', 72, 'demo_nodes_cpp/talker')
    robot.add(PID0 + 80, [LIB + 'x/foreign', '--ros-args', '--enclave', '/vizanti_node_start/nforged'])
    robot.add(PID0 + 81, [LIB + 'x/secured', '--ros-args', '--enclave', '/robot'])
    # enclave 가 node_start 가 붙이는 argv 꼬리에 있지 않다: argv 로 판단
    robot.add(PID0 + 82, [LIB + 'x/copied', '--ros-args', '--enclave', ts, '-r', '__node:=copied'])
    handler.graph = [
        ('turtlesim', '/', ts),
        ('amcl', '/', ts),                                         # 실제 /amcl(4) 과 겹친다
        ('talker', '/', t1), ('talker', '/', t2),                  # UI 로 같은 노드를 두 번 띄움
        ('ghost', '/', '/vizanti_node_start/nffffffffffffffff'),   # 이 enclave 를 단 프로세스는 없다
        ('renamed', '/', '/robot'),                                # node_start 의 enclave 가 아니다: 쓰지 않는다
    ]
    started = handler.started_nodes()
    assert sorted(started) == sorted([ts, t1, t2, '/vizanti_node_start/nffffffffffffffff'])
    for node, expected in [('/amcl', [4, 61]), ('/talker', [71, 73]), ('/turtlesim', [61]), ('/ghost', []),
                           ('/foreign', [80]), ('/secured', [81]), ('/renamed', []), ('/copied', [82])]:
        assert pids(sh.ServiceHandler.find_ros_node_pids(node, started=started)) == expected, node
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    for node in ('/amcl', '/talker'):
        res = handler.node_kill(Req(node=node), Res())
        assert res.success is False and 'Not killed: 2 processes' in res.message, node
    assert killer.sent == []


def test_node_kill_without_graph_goes_by_argv(robot, handler, monkeypatch):
    def unsupported():
        raise RuntimeError('rmw: enclaves unsupported')
    monkeypatch.setattr(handler, 'get_node_names_and_namespaces_with_enclaves', unsupported)
    killer = KillRecorder(robot)
    monkeypatch.setattr(os, 'kill', killer)
    res = handler.node_kill(Req(node='/collision_monitor'), Res())
    assert res.success is True and killer.sent == [(1, signal.SIGTERM)]


class FakeClock(object):
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _stop(robot, pid, start, kill, clock=None):
    clock = clock or FakeClock()
    return sh.ServiceHandler.stop_process(pid, start, grace=3.0, proc_root=robot.root,
                                          kill=kill, sleep=clock.sleep, clock=clock)


def test_stop_process_terminate_then_kill(robot):
    killer = KillRecorder(robot, exits_on=())  # 어떤 시그널에도 안 죽는 것으로 기록만
    clock = FakeClock()
    assert _stop(robot, PID0 + 4, b'1000', killer, clock) == 'SIGKILL'
    assert killer.sent == [(4, signal.SIGTERM), (4, signal.SIGKILL)]
    assert clock.now >= 3.0  # 유예 시간을 다 기다린 뒤에만 SIGKILL


def test_stop_process_exited_on_sigterm(robot):
    killer = KillRecorder(robot)
    assert _stop(robot, PID0 + 4, b'1000', killer) == 'SIGTERM'
    assert killer.sent == [(4, signal.SIGTERM)]


def test_stop_process_already_gone(robot):
    killer = KillRecorder(robot)
    robot.remove(PID0 + 4)
    assert _stop(robot, PID0 + 4, b'1000', killer) == 'already exited'
    assert killer.sent == []


def test_stop_process_never_signals_a_recycled_pid(robot):
    killer = KillRecorder(robot, exits_on=())
    # 매칭 이후 pid 가 다른 프로세스로 재사용됨 (시작 시각이 다름): 아무 시그널도 보내지 않는다
    assert _stop(robot, PID0 + 4, b'999', killer) == 'already exited'
    assert killer.sent == []

    # SIGTERM 직후 종료되고 같은 pid 가 재사용됨: SIGKILL 은 보내지 않는다
    def recycle(pid, sig):
        killer.sent.append((pid - PID0, sig))
        robot.set_stat(pid, start=5555)
    killer.sent = []
    assert _stop(robot, PID0 + 4, b'1000', recycle) == 'SIGTERM'
    assert killer.sent == [(4, signal.SIGTERM)]


def test_stop_process_zombie_counts_as_exited(robot):
    sent = []

    def to_zombie(pid, sig):
        sent.append(sig)
        robot.set_stat(pid, state='Z', start=1000)
    assert _stop(robot, PID0 + 4, b'1000', to_zombie) == 'SIGTERM'
    assert sent == [signal.SIGTERM]


# ---------------------------------------------------------------------------------------------
# [18] bag/setup
# ---------------------------------------------------------------------------------------------

UI_PATH = '~/2026-11-02-10-32-recording.bag'  # rosbag_script.js 가 보내는 형식


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / 'home' / 'rgt'
    (home / '.ssh').mkdir(parents=True)
    (home / '.config' / 'autostart').mkdir(parents=True)
    (home / 'bags').mkdir()
    (tmp_path / 'outside').mkdir()
    os.symlink(str(tmp_path / 'outside'), str(home / 'link_out'))
    (home / 'existing.bag').mkdir()
    monkeypatch.setenv('HOME', str(home))
    return str(home)


def _record(handler, path, topics):
    return handler.recording_setup(Req(start=True, path=path, topics=topics), None)


@pytest.mark.parametrize('topics', [
    ['-a'],
    ['--regex', '.*'],
    ['/scan', '-o', '/tmp/x'],
    ['--node-name', 'amcl'],
    ['--snapshot-mode', '--max-cache-size', '100'],
    ['--qos-profile-overrides-path', '/etc/hostname'],
    ['/scan', '--all'],
    ['/scan bad'],
    ['/scan', ''],
    ['/scan/'],
    [],
])
def test_bag_topic_injection_rejected(handler, home, fake_subprocess, topics):
    res = _record(handler, UI_PATH, topics)
    assert res.success is False
    assert fake_subprocess.calls == [] and handler.proc is None


@pytest.mark.parametrize('path', [
    '/home/rgt/.ssh/x',            # 리뷰 예시 (이 테스트의 홈 밖)
    '~/.ssh/x',                    # 숨김 디렉터리
    '~/.config/autostart/x.desktop',
    '/tmp/x',
    '~/../x',
    '~/link_out/x',                # 홈 안의 심볼릭 링크로 밖으로 탈출
    '/2026-11-02-10-32-recording.bag',  # UI 가 '/' 없는 경로를 루트로 만든 경우
    '~/',
    '~/-o',
    '~/.hidden_bag',
    '~/existing.bag',              # ros2 bag 이 어차피 거부: 조용한 실패 대신 오류로 돌려준다
])
def test_bag_path_confined(handler, home, fake_subprocess, path):
    res = _record(handler, path, ['/scan'])
    assert res.success is False
    assert fake_subprocess.calls == [] and handler.proc is None


@pytest.mark.parametrize('path, rel', [
    (UI_PATH, '2026-11-02-10-32-recording.bag'),
    ('~/bags/run1', 'bags/run1'),
    ('bags/new_dir/run2', 'bags/new_dir/run2'),   # 상대 경로는 홈 기준
])
def test_bag_record_valid(handler, home, fake_subprocess, path, rel):
    res = _record(handler, path, ['/scan', '/tf', '/robot1/_action/status'])
    assert res.success is True
    assert fake_subprocess.calls == [['ros2', 'bag', 'record', '-o', os.path.join(home, rel),
                                      '/scan', '/tf', '/robot1/_action/status']]
    stop = handler.recording_setup(Req(start=False, path='', topics=[]), None)
    assert stop.success is True and fake_subprocess.procs[0].terminated and handler.proc is None
