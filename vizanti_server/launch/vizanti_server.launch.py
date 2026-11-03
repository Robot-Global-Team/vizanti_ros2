import launch
import launch_ros.actions

def generate_launch_description():

    #general params
    #security: flask/rosbridge are loopback-only backends; the only externally
    #exposed port is the authenticating gateway (vizanti_gateway.py) on port_public.
    #Dev mode without the gateway: port_public:=5001 and open http://127.0.0.1:5002
    #rosbridge stays on 5001 (loopback): the on-board GUI hardcodes ws://localhost:5001 (rgt_ros2_gui useRosbridge.ts)
    base_url = launch.substitutions.LaunchConfiguration('base_url', default='') #e.g. /vizanti
    port = launch.substitutions.LaunchConfiguration('port', default=5002) #flask backend (127.0.0.1)
    port_rosbridge = launch.substitutions.LaunchConfiguration('port_rosbridge', default=5001) #rosbridge backend (127.0.0.1)
    port_public = launch.substitutions.LaunchConfiguration('port_public', default=5000) #gateway port the browser connects to
    flask_debug = launch.substitutions.LaunchConfiguration('flask_debug', default=False)
    default_widget_config = launch.substitutions.LaunchConfiguration('default_widget_config', default='') #e.g. ~/your_custom_config.json

    #rosbridge internal params
    send_action_goals_in_new_thread = launch.substitutions.LaunchConfiguration('send_action_goals_in_new_thread', default='true')
    call_services_in_new_thread = launch.substitutions.LaunchConfiguration('call_services_in_new_thread', default='true')
    unregister_timeout = launch.substitutions.LaunchConfiguration('unregister_timeout', default='9999999.9')
    retry_startup_delay = launch.substitutions.LaunchConfiguration('retry_startup_delay', default='10.0')
    fragment_timeout = launch.substitutions.LaunchConfiguration('fragment_timeout', default='30')
    delay_between_messages = launch.substitutions.LaunchConfiguration('delay_between_messages', default='0.0')
    max_message_size = launch.substitutions.LaunchConfiguration('max_message_size', default='999999999')
    websocket_ping_interval = launch.substitutions.LaunchConfiguration('websocket_ping_interval', default='4.0')
    websocket_ping_timeout = launch.substitutions.LaunchConfiguration('websocket_ping_timeout', default='15.0')

    rosbridge_node = launch_ros.actions.Node(
        name='vizanti_rosbridge',
        package='rosbridge_server',
        executable='rosbridge_websocket',
        output='screen',
        parameters=[
            #note: rosbridge 2.x (ROS 2) ignores 'authenticate' - auth is done by vizanti_gateway.py in front
            {'port': port_rosbridge},
            {'address': '127.0.0.1'},
            {'retry_startup_delay': retry_startup_delay},
            {'fragment_timeout': fragment_timeout},
            {'delay_between_messages': delay_between_messages},
            {'max_message_size': max_message_size},
            {'unregister_timeout': unregister_timeout},
            {'use_compression': True},
            {'websocket_ping_interval': websocket_ping_interval},
            {'websocket_ping_timeout': websocket_ping_timeout},
            {'send_action_goals_in_new_thread': send_action_goals_in_new_thread},
            {'call_services_in_new_thread': call_services_in_new_thread}
        ]
    )

    rosapi_node = launch_ros.actions.Node(
        name='rosapi',
        package='rosapi',
        executable='rosapi_node'
    )

    flask_node = launch_ros.actions.Node(
        name='vizanti_flask_node',
        package='vizanti_server',
        executable='server.py',
        output='screen',
        parameters=[
            {'host': '127.0.0.1'},
            {'port': port},
            {'port_rosbridge': port_public}, #what the browser is told to open - the gateway splices ws to port_rosbridge
            {'flask_debug': flask_debug},
            {'base_url': base_url},
            {'compression': "none"},
            {'default_widget_config': default_widget_config}
        ]
    )

    tf_handler_node = launch_ros.actions.Node(
        name='vizanti_tf_handler_node',
        package='vizanti_cpp',
        executable='tf_consolidator',
        output='screen'
    )

    service_handler_node = launch_ros.actions.Node(
        name='vizanti_service_handler_node',
        package='vizanti_server',
        executable='service_handler.py',
        output='screen'
    )

    return launch.LaunchDescription([
        rosbridge_node,
        rosapi_node,
        flask_node,
        tf_handler_node,
        service_handler_node
    ])

if __name__ == '__main__':
    launch.main()
