FROM ne0nd0g/merlin-base:v1.8.0

# Build multi-arch Docker image and push tagged version to Docker Hub
# > sudo docker buildx build --push --platform linux/amd64,linux/arm64 --tag ne0nd0g/merlin-mythic:v1.0.2 --tag ne0nd0g/merlin-mythic:latest .

WORKDIR /Mythic

# Copy in merlin/Payload_Type/merlin (location where this Docker file is) into the Docker image at /Mythic
COPY [".", "."]

# Download all the Go modules ahead of time, before compiling
WORKDIR /Mythic/agent
RUN go mod download
WORKDIR /Mythic/container
RUN go mod download

# Build the Merlin container and save in the /usr/local/bin directory because it is in the PATH environment variable
# Do not save it in the Mythic directory because it is temporary while building and will be lost
RUN go build -o /usr/local/bin/MerlinContainer

CMD /usr/local/bin/MerlinContainer