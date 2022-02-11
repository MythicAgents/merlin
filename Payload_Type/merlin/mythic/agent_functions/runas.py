
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class RunAsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="Username",
                type=ParameterType.String,
                description="Domain and username to make a token for (e.g. ACME\\RASTLEY",
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
                name="executable",
                cli_name="executable",
                display_name="Executable",
                type=ParameterType.String,
                description="The executable program to start",
                value="whoami",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=3,
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
                    ui_position=4,
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
                if len(args) < 3:
                    raise Exception("Expected 3 or more arguments")

                self.add_arg("user", args[0])
                self.add_arg("pass", args[1])
                self.add_arg("executable", args[2])
                if len(args) > 3:
                    self.add_arg("arguments", " ".join(args[3:]))


class RunAsCommand(CommandBase):
    cmd = "runas"
    needs_admin = False
    help_cmd = "runas"
    description = "Run the provided program as the user for the provided credentials"
    version = 1
    author = "@Ne0nd0g"
    argument_class = RunAsArguments
    attackmapping = ["T1106"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        # RunAs Arguments <user>, <pass>, <executable>, [<args>]
        args = [task.args.get_arg("user"), task.args.get_arg("pass"), task.args.get_arg("executable")]

        if task.args.get_arg("arguments"):
            task.display_params = f'User: {task.args.get_arg("user")} Pass: {task.args.get_arg("pass")} ' \
                                  f'Program: {task.args.get_arg("executable")} {task.args.get_arg("arguments")}'
            arguments = task.args.get_arg("arguments").split()
            if len(arguments) == 1:
                args.append(arguments[0])
            elif len(arguments) > 1:
                for arg in arguments:
                    args.append(arg)
        else:
            task.display_params = f'User: {task.args.get_arg("user")} Pass: {task.args.get_arg("pass")} ' \
                                  f'Program: {task.args.get_arg("executable")}'

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.remove_arg("user")
        task.args.remove_arg("pass")
        task.args.remove_arg("executable")
        task.args.remove_arg("arguments")
        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
