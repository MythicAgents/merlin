
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class RunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="arguments",
                cli_name="args",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to start the executable with",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=1,
                    required=False,
                )],
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
                    ui_position=0,
                    required=True,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("executable", args[0])
                if len(args) > 1:
                    self.add_arg("arguments", " ".join(args[1:]))


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run"
    description = "Run the executable with the provided arguments and return the results"
    version = 1
    author = "@Ne0nd0g"
    argument_class = RunArguments
    attackmapping = ["T1106"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        # Executable Arguments
        args = []
        # TODO Handle argument parsing when quotes and escapes are used
        if task.args.get_arg("arguments"):
            task.display_params = f'{task.args.get_arg("executable")} {task.args.get_arg("arguments")}'
            arguments = task.args.get_arg("arguments").split()
            if len(arguments) == 1:
                args.append(arguments[0])
            elif len(arguments) > 1:
                for arg in arguments:
                    args.append(arg)
        else:
            task.display_params = f'{task.args.get_arg("executable")}'

        # Merlin jobs.Command message type
        command = {
            "command": task.args.get_arg("executable"),
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.CMD, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("executable")
        task.args.remove_arg("arguments")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
