# Merlin

<p align="center">
  <img src="https://i.imgur.com/4iKuvuj.jpg" height="30%" width="30%">
</p>

Cross-platform post-exploitation HTTP Command &amp; Control agent written in golang

This repository is a port of the Merlin agent from <https://github.com/Ne0nd0g/merlin> to run on the Mythic framework.
This implementation uses Mythic's [Default HTTP](https://docs.mythic-c2.net/c2-profiles/http) Command and Control profile

Merlin documentation can be found at <https://merlin-c2.readthedocs.io/en/latest/index.html>

Mythic documentation can be found at <https://docs.mythic-c2.net/>

## Getting Started

To get started:

1. Clone the [Mythic](https://github.com/its-a-feature/Mythic/) repository
2. Pull down the [http](https://github.com/MythicC2Profiles/http) C2 profile from the MythicC2Profiles organization
3. Pull down the [Merlin](https://github.com/MythicAgents/merlin) agent from the MythicAgents organization
4. Start Mythic
5. Navigate to <https://127.0.0.1:7443> and login with a username of `mythic_admin` and password retrieved from the `.env` file

This code snippet will execute most of the getting started steps:
```text
cd ~/
git clone https://github.com/its-a-feature/Mythic
cd Mythic/
sudo make
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicAgents/merlin
sudo ./mythic-cli start
sudo cat .env | grep MYTHIC_ADMIN_PASSWORD
```

Use the following commands to run the Merlin container from the command line without using Docker:

> **NOTE: Replace the RabbitMQ password with the one from the `.env` file in the root Mythic folder**

```bash
cd merlin/Payload_Type/merlin/container
export MYTHIC_SERVER_HOST="127.0.0.1"
export RABBITMQ_HOST="127.0.0.1"
export RABBITMQ_PASSWORD="K5SHkn1fk2pcT0YkQxTTMgO5gFwjiQ"
go run main.go
```

## Known Limitations
The table captures known limitations of the Merlin agent on the Mythic framework.

| Feature       | Status          | Notes         |
|---------------|-----------------|---------------|
| MiniDump      | Not Implemented |               |
| File Chunking | Not Implemented |               |
