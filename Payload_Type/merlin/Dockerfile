# pull in the appropriate language's payload container from itsafeaturemythic on dockerhub
From itsafeaturemythic/xgolang_payload:0.0.7

# Update APT
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y apt-transport-https gpg git

# Install Microsoft package signing key
RUN wget --quiet -O - https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
RUN mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
RUN wget --quiet https://packages.microsoft.com/config/debian/9/prod.list
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

# Update PATH
ENV PATH="${PATH}:/go/src/bin"

# Download go-donut
RUN go get github.com/Binject/go-donut
