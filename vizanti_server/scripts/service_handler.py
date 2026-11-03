#!/usr/bin/env python3

import re
import subprocess
import os
import fcntl
import signal
import sys
import rclpy
import json
import time

from rclpy.node import Node

from rclpy.executors import  MultiThreadedExecutor
from rclpy.callback_groups import ReentrantCallbackGroup

from ros2lifecycle.api import get_node_names
from ros2pkg.api import get_package_names, get_prefix_path
from rqt_reconfigure_param_api import create_param_client
from rclpy.parameter import Parameter
from rcl_interfaces.msg import ParameterDescriptor

from std_srvs.srv import Trigger
from vizanti_msgs.srv import GetNodeParameters, SetNodeParameter
from vizanti_msgs.srv import LoadMap, SaveMap
from vizanti_msgs.srv import RecordRosbag
from vizanti_msgs.srv import ManageNode, ListPackages, ListExecutables, ListLifecycles

from lifecycle_msgs.srv import GetState
from lifecycle_msgs.msg import State

# vizanti/node/start reaches subprocess straight from rosbridge, so it may only run an
# executable / launch file of an installed ROS package - never an arbitrary command line.
_START_VERBS = {'ros2 run', 'ros2 launch'}
_START_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]*$')
_START_ARG_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_/~.\-]*:=[A-Za-z0-9_/~.,:\-]*$')
# a launch argument name has no '-', which also rules out launch-prefix / launch-prefix-filter:
# launch.descriptions.Executable puts that launch configuration in front of EVERY process it starts
_LAUNCH_ARG_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*:=[A-Za-z0-9_/~.,:\-]*$')

# ROS 2 node / topic name: tokens never start with a digit or '-', so a name is never read as an option
_ROS_NAME_RE = re.compile(r'^/?(?:[A-Za-z_][A-Za-z0-9_]*/)*[A-Za-z_][A-Za-z0-9_]*\Z')
_FILE_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]*\Z')
_PYTHON_RE = re.compile(r'^python[0-9.]*\Z')
# rcl (Jazzy) flags inside --ros-args that take the next argv token as their value, whatever it looks like
_ROS_VALUE_FLAGS = ('-p', '--param', '--params-file', '-e', '--enclave', '--log-level', '--log-file-name',
                    '--log-config-file')
# node/start gives every `ros2 run` process an enclave of its own below this; the ROS graph lists the enclave next
# to each node of the process, which is how node/kill tells what such a process runs
_START_ENCLAVE = '/vizanti_node_start/'
_PROC = '/proc'
_KILL_GRACE = 3.0  # seconds a node gets to exit on SIGTERM before SIGKILL


def _start_arg_error(verb, arg):
    """Why node/start refuses the run/launch argument `arg` (None = acceptable name:=value)."""
    key = arg.split(':=', 1)[0]
    if key.startswith('__'):
        return 'reserved ROS argument'  # __node, __ns, __params, __log_level, ...
    if key.lower().replace('-', '_').startswith('launch_prefix'):
        return 'launch prefix is not allowed'  # would run any binary as argv[0] of every launched node
    if not (_LAUNCH_ARG_RE if verb == 'ros2 launch' else _START_ARG_RE).match(arg):
        return 'only name:=value'
    return None


def _split_node_name(node):
    """'/ns/sub/name' -> ('/ns/sub', 'name'); ValueError unless it is a valid ROS 2 node name."""
    node = str(node).strip()
    if not _ROS_NAME_RE.match(node):
        raise ValueError('invalid node name ' + repr(node))
    parts = node.strip('/').split('/')
    return '/' + '/'.join(parts[:-1]), parts[-1]


def _proc_stat(pid, proc_root):
    """(state, start time) of a process, None once it is gone."""
    try:
        with open(os.path.join(proc_root, str(pid), 'stat'), 'rb') as f:
            data = f.read()
    except OSError:
        return None
    fields = data[data.rfind(b')') + 1:].split()  # comm may contain spaces and ')'
    return (fields[0], fields[19]) if len(fields) > 19 else None


def _ros_node_identity(argv):
    """(namespace, name) a ROS 2 node process runs as, from its argv tokens; None for anything else."""
    if '--ros-args' not in argv:
        return None
    first = 1 if _PYTHON_RE.match(os.path.basename(argv[0])) and len(argv) > 1 else 0
    exe = os.path.basename(argv[first])  # python node: the script is the executable (and rclpy's argv[0])
    if exe == 'ros2':
        return None  # the `ros2 run` CLI carries the same --ros-args as the node it spawned
    # read argv as rcl does: one rule list in argv order, argv[0] included, and the first rule of a kind wins
    rules, ros_args, i = {}, False, first
    while i < len(argv):
        rule = None
        if argv[i] == '--ros-args':
            ros_args = True
        elif not ros_args:
            rule = argv[i]  # rcl still applies a bare 'a:=b' outside --ros-args (deprecated syntax)
        elif argv[i] == '--':
            ros_args = False
        elif argv[i] in ('-r', '--remap') and i + 1 < len(argv):
            i += 1
            rule = argv[i]
        elif argv[i] in _ROS_VALUE_FLAGS:
            i += 1
        if rule is not None:
            lhs, sep, rhs = rule.partition(':=')
            key = lhs.rsplit(':', 1)[-1]
            kind = '__node' if key == '__name' else key  # rcl lexer: '__node or __name'
            if sep and kind in ('__node', '__ns') and kind not in rules:
                if ':' in lhs or not ros_args:
                    return None  # rule for one named node only / deprecated syntax rcl may not parse: undecidable
                rules[kind] = rhs
        i += 1
    ns = rules.get('__ns')
    return ('/' if ns is None else '/' + ns.strip('/')), rules.get('__node', exe)


def _bag_output(path):
    """New `ros2 bag record -o` directory inside the home directory: no hidden dir, no '..'/symlink escape."""
    home = os.path.realpath(os.path.expanduser('~'))
    path = os.path.join(home, os.path.expanduser(str(path)))  # a relative path is taken from home
    name = os.path.basename(path)
    if not _FILE_NAME_RE.match(name):
        raise ValueError('invalid bag name ' + repr(name))
    parent = os.path.realpath(os.path.dirname(path))
    prefix = home.rstrip(os.sep) + os.sep
    if parent != home and not parent.startswith(prefix):
        raise ValueError('bag path must be inside ' + home)
    if any(p.startswith('.') for p in parent[len(prefix):].split(os.sep)):
        raise ValueError('bag path must not be in a hidden directory')
    out = os.path.join(parent, name)
    if os.path.lexists(out):
        raise ValueError(out + ' already exists')
    return out


def _bag_command(path, topics):
    """argv for `ros2 bag record`: validated topic names only ('-a', '--regex', '-o x' would be options)."""
    topics = [str(t) for t in topics]
    if not topics:
        raise ValueError('no topics selected')
    for topic in topics:
        if not _ROS_NAME_RE.match(topic):
            raise ValueError('invalid topic ' + repr(topic))
    return ['ros2', 'bag', 'record', '-o', _bag_output(path)] + topics


class ServiceHandler(Node):
    def __init__(self, group):
        super().__init__("vizanti_service_handler")

        self.proc = None
        self.packages = sorted(list(get_package_names()))
        # optional extra restriction, comma separated package names ('' = any installed package).
        # read-only: set it from the launch file - vizanti/set_node_parameter must not be able to widen it
        self.declare_parameter('node_start_allowed_packages', '', ParameterDescriptor(read_only=True))

        self.get_node_parameters_service = self.create_service(GetNodeParameters, 'vizanti/get_node_parameters', self.get_node_parameters, callback_group=group)
        self.set_node_parameter_service = self.create_service(SetNodeParameter, 'vizanti/set_node_parameter', self.set_node_parameter, callback_group=group)

        self.record_setup_service = self.create_service(RecordRosbag, 'vizanti/bag/setup', self.recording_setup, callback_group=group)

        self.kill_service = self.create_service(ManageNode, 'vizanti/node/kill', self.node_kill, callback_group=group)
        self.start_service = self.create_service(ManageNode, 'vizanti/node/start', self.node_start, callback_group=group)
        self.info_service = self.create_service(ManageNode, 'vizanti/node/info', self.node_info, callback_group=group)
        self.wtf_service = self.create_service(Trigger, 'vizanti/roswtf', self.roswtf, callback_group=group)
        self.record_status_service = self.create_service(Trigger, 'vizanti/bag/status', self.recording_status, callback_group=group)
        self.list_lifecycle_service = self.create_service(ListLifecycles, 'vizanti/list_lifecycle_nodes', self.list_lifecycle_nodes_status, callback_group=group)

        self.list_packages_service = self.create_service(ListPackages, 'vizanti/list_packages', self.list_packages_callback, callback_group=group)
        self.list_executables_service = self.create_service(ListExecutables, 'vizanti/list_executables', self.list_executables_callback, callback_group=group)

        self.get_logger().info("Service handler ready.")

    def list_lifecycle_nodes_status(self, req, res):
        node_names = get_node_names(node=self, include_hidden_nodes=True)
        fullnames = [n.full_name for n in node_names]
        state_ids = [0] * len(fullnames)

        for i in range(len(fullnames)):
            try:
                client = self.create_client(GetState,f'{fullnames[i]}/get_state')
                response = client.call(GetState.Request())
                state_ids[i] = response.current_state.id
            except:
                pass

        res.nodes = fullnames
        res.states = state_ids
        return res

    def list_packages_callback(self, req, res):
        res.packages = self.packages
        return res

    def get_filenames(self, file_paths):
        file_names = []
        for file_path in file_paths:
            base_name = os.path.basename(file_path)
            if base_name.endswith(tuple([".py",".launch",".yaml"])) or "." not in base_name:
                file_names.append(base_name)
        return file_names

    def list_executables_callback(self, req, res):

        if req.package not in self.packages:
            self.get_logger().error("Package not found: " + req.package)
            res.executables = []
            return res
        
        path = get_prefix_path(req.package)

        #TODO add path to apt installed packages, I'm not sure where exactly those executables are yet
        #self.get_logger().info(f"libpath: {libpath}")

        cmd_exec = ["find", path+"/share/"+req.package] # get list of executables
        cmd_exec = cmd_exec + ["-type", "f", "-o", "-type", "l"] # files or symlinks

        cmd_launch = ["find", path+"/lib/"+req.package]
        cmd_launch = cmd_launch + ["-type", "f", "-o", "-type", "l"]
        process_exec = subprocess.Popen(cmd_exec, stdout=subprocess.PIPE)
        process_launch = subprocess.Popen(cmd_launch, stdout=subprocess.PIPE)

        output_exec, _ = process_exec.communicate()
        output_launch, _ = process_launch.communicate()

        # Process output
        lines_exec = self.get_filenames(output_exec.decode('utf-8').split('\n'))
        lines_launch = self.get_filenames(output_launch.decode('utf-8').split('\n'))

        self.get_logger().info(f"lines_exec: {lines_exec}")
        self.get_logger().info(f"output_python_and_launch: {lines_launch}")

        executables = [line.split("/")[-1] for line in lines_exec if line]
        launch_files = [line.split("/")[-1] for line in lines_launch if line]

        res.executables = executables + launch_files
        return res

    @staticmethod
    def find_ros_node_pids(node, proc_root=None, started=None):
        #security: exact match, never a substring. `node` becomes (namespace, name) and is compared with what
        #each ROS 2 process runs as: its node name / namespace remap rules read from argv as rcl reads them,
        #else its executable name. a process whose argv cannot decide its name is never a candidate, nor is
        #any process without --ros-args (desktop, editors, daemons).
        #a process that node/start gave an enclave listed in `started` (see started_nodes) runs exactly the nodes
        #the ROS graph lists for that enclave, whatever its executable name (turtlesim_node runs /turtlesim).
        #returns [(pid, start time)] so a recycled pid is never signalled.
        proc_root = proc_root or _PROC
        want = _split_node_name(node)
        started = started or {}
        skip = {os.getpid(), os.getppid(), 1}
        hits = []
        for entry in os.listdir(proc_root):
            if not entry.isdigit() or int(entry) in skip:
                continue
            stat = _proc_stat(entry, proc_root)  # before cmdline: a recycled pid then fails the start time check
            if stat is None or stat[0] in (b'Z', b'X'):
                continue
            try:
                with open(os.path.join(proc_root, entry, 'cmdline'), 'rb') as f:
                    argv = f.read().split(b'\0')
            except OSError:
                continue
            if argv[-1] == b'':
                argv.pop()  # cmdline ends with NUL
            argv = [a.decode('utf-8', 'replace') for a in argv]
            identity = argv and _ros_node_identity(argv)
            if not identity:
                continue  # also the `ros2 run` CLI, which carries the same enclave as its node
            names = started.get(argv[-1]) if argv[-3:-1] == ['--ros-args', '--enclave'] else None
            if (want in names) if names is not None else (identity == want):
                hits.append((int(entry), stat[1]))
        return hits

    @staticmethod
    def stop_process(pid, start, grace=None, proc_root=None, kill=None, sleep=None, clock=None):
        """SIGTERM, then SIGKILL only if the same process (pid + start time) is still alive after `grace` s."""
        proc_root = proc_root or _PROC
        kill = kill or os.kill
        sleep = sleep or time.sleep
        clock = clock or time.monotonic
        grace = _KILL_GRACE if grace is None else grace

        def alive():
            stat = _proc_stat(pid, proc_root)
            return stat is not None and stat[1] == start and stat[0] not in (b'Z', b'X')

        if not alive():
            return 'already exited'
        try:
            kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return 'already exited'
        deadline = clock() + grace
        while alive():
            if clock() >= deadline:
                try:
                    kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    break
                return 'SIGKILL'
            sleep(0.1)
        return 'SIGTERM'

    def started_nodes(self):
        """{enclave: {(namespace, name)}} from the ROS graph, for the enclaves node/start hands out."""
        try:
            graph = self.get_node_names_and_namespaces_with_enclaves()
        except Exception as e:  # node/kill then goes by argv alone
            self.get_logger().warning('no node enclaves from the ROS graph: ' + str(e))
            return {}
        started = {}
        for name, ns, enclave in graph:
            if enclave.startswith(_START_ENCLAVE):
                started.setdefault(enclave, set()).add((ns, name))
        return started

    def node_kill(self, req, res):
        try:
            #ros 2 doesn't let you kill nodes in a legit way, so we have to be extra janky lol
            #this seems to also have the weird side effect that it takes a year for ros2 node list to show the change
            self.get_logger().info("Attempting to kill node "+str(req.node))
            matches = self.find_ros_node_pids(req.node, started=self.started_nodes())
            if len(matches) != 1:
                # nothing to kill, or ambiguous: kill nothing rather than guess
                res.success = False
                if matches:
                    res.message = f'Not killed: {len(matches)} processes run as node {req.node} (pids: {[pid for pid, _ in matches]})'
                else:
                    res.message = f'No running process found for node {req.node}'
                return res
            pid, start = matches[0]
            res.success = True
            res.message = f'Killed node {req.node} (pid {pid}, {self.stop_process(pid, start)})'
        except Exception as e:
            res.success = False
            res.message = str(e)
        return res

    def start_command(self, command):
        """Validated argv for node/start: '<verb> <installed package> <name> [arg:=value ...]'."""
        tokens = str(command).split()
        verb_len = 2 if tokens[:1] == ['ros2'] else 1
        verb = ' '.join(tokens[:verb_len])
        if len(tokens) < verb_len + 2 or verb not in _START_VERBS:
            raise ValueError('expected: ' + ' | '.join(sorted(_START_VERBS)) + ' <package> <name> [arg:=value ...]')
        package, name, args = tokens[verb_len], tokens[verb_len + 1], tokens[verb_len + 2:]
        if not _START_NAME_RE.match(package) or package not in self.packages:
            raise ValueError('unknown package ' + repr(package))
        allowed = [p.strip() for p in str(self.get_parameter('node_start_allowed_packages').value).split(',') if p.strip()]
        if allowed and package not in allowed:
            raise ValueError('package ' + repr(package) + ' is not in node_start_allowed_packages')
        if not _START_NAME_RE.match(name):
            raise ValueError('invalid executable/launch name ' + repr(name))
        for arg in args:
            reason = _start_arg_error(verb, arg)
            if reason:
                raise ValueError('invalid argument ' + repr(arg) + ' (' + reason + ')')
        return tokens[:verb_len] + [package, name] + args

    def node_start(self, req, res):
        try:
            args = self.start_command(req.node)
            if args[:2] == ['ros2', 'run']:
                # node/kill only takes processes with --ros-args for ROS 2 nodes; `ros2 run` hands everything after
                # the executable name to the node, and rcl accepts an empty --ros-args
                args.append('--ros-args')
                if os.environ.get('ROS_SECURITY_ENABLE') != 'true':  # SROS2 on: the enclave selects the keystore entry
                    args += ['--enclave', _START_ENCLAVE + 'n' + os.urandom(8).hex()]  # a name token: no leading digit

            # Open /dev/null
            devnull = open(os.devnull, 'w')

            # Set up the process to ignore the SIGTERM signal
            def preexec():
                os.setpgrp()
                sys.stdin = open(os.devnull, 'r')
                sys.stdout = open(os.devnull, 'w')
                sys.stderr = open(os.devnull, 'w')

            subprocess.Popen(args, stdout=devnull, stderr=devnull, preexec_fn=preexec)

            self.get_logger().info("Starting node "+str(req.node))

            res.success = True
            res.message = f'Started node {req.node}'
        except Exception as e:
            res.success = False
            res.message = str(e)
        return res

    def node_info(self, req, res):
        try:
            rosinfo = subprocess.check_output(["ros2", "node", "info", req.node]).decode('utf-8')
            rosinfo = rosinfo.replace("--------------------------------------------------------------------------------", "")
            res.success = True
            res.message = rosinfo
        except Exception as e:
            res.success = False
            res.message = str(e)
        return res

    def roswtf(self, req, res):
        try:
            self.get_logger().info("Compiling doctor report...")
            rosinfo = subprocess.check_output(["ros2", "doctor", "--report"]).decode('utf-8')
            res.success = True
            res.message = rosinfo
        except Exception as e:
            res.success = False
            res.message = str(e)
        return res

    def get_node_parameters(self, req, res):
        try:
            param_client = create_param_client(self, req.node)
            param_names = param_client.list_parameters()
            descriptors = param_client.describe_parameters(param_names)
            #Parameter.Type Enum
            #  <Type.NOT_SET: 0>,
            #  <Type.BOOL: 1>,
            #  <Type.INTEGER: 2>,
            #  <Type.DOUBLE: 3>,
            #  <Type.STRING: 4>,
            #  <Type.BYTE_ARRAY: 5>,
            #  <Type.BOOL_ARRAY: 6>,
            #  <Type.INTEGER_ARRAY: 7>,
            #  <Type.DOUBLE_ARRAY: 8>,
            #  <Type.STRING_ARRAY: 9>

            parameters = param_client.get_parameters(param_names)
            param_list = []
            for param, descriptor in zip(parameters, descriptors):
                if descriptor.type > 0 and descriptor.type < 5: #TODO add support for the rest if anyone actually uses them
                    param_list.append([param.name, param.value, descriptor.type])
            res.parameters = json.dumps(param_list)            
        except Exception as e:
            res.parameters = "[]"
            print(f"Failed to fetch parameters from node: {e}")
        return res
    
    def set_node_parameter(self, req, res):
        try:
            param_client = create_param_client(self, req.node)
            descriptors = param_client.describe_parameters([req.param])
            param_type = Parameter.Type(descriptors[0].type)

            value = req.value
            if param_type == Parameter.Type.BOOL:
                value = value == "true"
            elif param_type == Parameter.Type.INTEGER:
                value = int(value)
            elif param_type == Parameter.Type.DOUBLE:
                value = float(value)
            """elif param_type == Parameter.Type.BYTE_ARRAY:
                value = int(value)
            elif param_type == Parameter.Type.BOOL_ARRAY:
                value = int(value)
            elif param_type == Parameter.Type.DOUBLE_ARRAY:
                value = int(value)
            elif param_type == Parameter.Type.STRING_ARRAY:
                value = int(value)"""
            
            self.get_logger().info(f"Setting {req.node}/{req.param} to {value}")

            parameter = Parameter(name=req.param, type_=param_type, value=value)
            param_client.set_parameters([parameter])
            res.status = "Ok."
        except Exception as e:
            res.status = "Error, could not set param."
        return res

    def recording_status(self, req, res):
        response = Trigger.Response()
        response.success = self.proc is not None

        if response.success:
            response.message = "Bag recording in progress..."
        else:
            response.message = "Bag recorder idle."

        return response

    def recording_setup(self, req, res):
        response = RecordRosbag.Response()

        if req.start:
            if self.proc is not None:
                response.success = False
                response.message = "Already recording, please stop the current recording first."
            else:
                try:
                    # output: a new directory below the home directory; topics: validated names only
                    command = _bag_command(req.path, req.topics)
                except ValueError as e:
                    response.success = False
                    response.message = str(e)
                    return response

                # Use subprocess to start rosbag record in a new process
                self.proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                response.success = True
                response.message = "Recording started."

                self.get_logger().info("Recording ros2 bag to "+str(command[4]))
        else:
            if self.proc is not None:
                # Terminate the rosbag record process
                self.proc.terminate()
                self.proc.wait()
                self.proc = None
                response.success = True
                response.message = "Recording stopped."

                self.get_logger().info("Recording stopped.")
            else:
                response.success = False
                response.message = "No active recording found."
                self.get_logger().info("No active recording found.")

        return response

def main(args=None):
    rclpy.init(args=args)

    service_handler = ServiceHandler(group=ReentrantCallbackGroup())
    executor = MultiThreadedExecutor(num_threads=20)
    executor.add_node(service_handler)

    try:
        executor.spin()
    except rclpy.executors.ExternalShutdownException:
        pass

    service_handler.destroy_node()
    rclpy.shutdown()

if __name__ == "__main__":
    main()
