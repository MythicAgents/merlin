# pull in the appropriate language's payload container from itsafeaturemythic on dockerhub
FROM python:3.8-slim-buster

# Update APT
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y apt-transport-https gpg git wget unzip

# It is WAY easier to install Go on the Python container instead of install Python 3.8 on the Golang 1.16 container
# Install Go
WORKDIR /opt/
RUN wget https://golang.org/dl/go1.16.5.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.5.linux-amd64.tar.gz
RUN rm /opt/go1.16.5.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"

# Configure Mythic Packages
RUN pip install aio_pika requests mythic-payloadtype-container==0.0.44 dynaconf==3.1.4

# Install Microsoft package signing key
RUN wget --quiet -O - https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
RUN mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
RUN wget --quiet https://packages.microsoft.com/config/debian/10/prod.list
RUN mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
RUN chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
RUN chown root:root /etc/apt/sources.list.d/microsoft-prod.list

# Install Microsoft .NET Core 2.1 SDK
RUN apt-get update
RUN apt-get install -y dotnet-sdk-2.1

# Build SharpGen
WORKDIR /opt/
RUN git clone https://github.com/cobbr/SharpGen
WORKDIR /opt/SharpGen
RUN dotnet build -c release

# Download sRDI
WORKDIR /opt/
RUN mkdir sRDI
WORKDIR /opt/sRDI/
RUN wget https://raw.githubusercontent.com/monoxgas/sRDI/master/Python/ShellcodeRDI.py
RUN wget https://raw.githubusercontent.com/monoxgas/sRDI/master/Python/ConvertToShellcode.py

# Download Mimikatz
WORKDIR /opt/
RUN wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
RUN unzip mimikatz_trunk.zip -d mimikatz
RUN rm /opt/mimikatz_trunk.zip

# Update PATH
ENV PATH="${PATH}:/root/go/bin"

# Download go-donut
RUN go get github.com/Binject/go-donut

# Download Garble
RUN go get mvdan.cc/garble

ENTRYPOINT ["/Mythic/mythic/payload_service.sh"]
