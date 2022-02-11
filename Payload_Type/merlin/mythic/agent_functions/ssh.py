
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class SSHArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="Username",
                type=ParameterType.String,
                description="Username to SSH with",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="pass",
                cli_name="pass",
                display_name="Password",
                type=ParameterType.String,
                description="The account's password",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=2,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="host",
                cli_name="host",
                display_name="host",
                type=ParameterType.String,
                description="The target host:port",
                default_value="127.0.0.1:22",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=3,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="executable",
                cli_name="executable",
                display_name="Executable",
                type=ParameterType.String,
                description="The executable program to start",
                value="whoami",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=4,
                    required=True,
                )],
            ),
            CommandParameter(
                name="arguments",
                cli_name="args",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to start the executable with",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=5,
                    required=False,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) < 4:
                    raise Exception("Expected 4 or more arguments")

                self.add_arg("user", args[0])
                self.add_arg("pass", args[1])
                self.add_arg("pass", args[2])
                self.add_arg("executable", args[3])
                if len(args) > 4:
                    self.add_arg("arguments", " ".join(args[4:]))


class SSHCommand(CommandBase):
    cmd = "ssh"
    needs_admin = False
    help_cmd = "ssh"
    description = "Connect to target host over the SSH protocol, executes the provided command, and returns the results."
    version = 1
    author = "@Ne0nd0g"
    argument_class = SSHArguments
    attackmapping = ["T1021.004"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        # SSH Arguments <user>, <pass>, <host>, <executable>, [<args>]
        args = [
            task.args.get_arg("user"),
            task.args.get_arg("pass"),
            task.args.get_arg("host"),
            task.args.get_arg("executable")
        ]

        if task.args.get_arg("arguments"):
            task.display_params = f'{task.args.get_arg("user")}@{task.args.get_arg("host")} ' \
                                  f'Program: {task.args.get_arg("executable")} {task.args.get_arg("arguments")}'
            arguments = task.args.get_arg("arguments").split()
            if len(arguments) == 1:
                args.append(arguments[0])
            elif len(arguments) > 1:
                for arg in arguments:
                    args.append(arg)
        else:
            task.display_params = f'{task.args.get_arg("user")}@{task.args.get_arg("host")} ' \
                                  f'Program: {task.args.get_arg("executable")}'

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.remove_arg("user")
        task.args.remove_arg("pass")
        task.args.remove_arg("host")
        task.args.remove_arg("executable")
        task.args.remove_arg("arguments")
        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
