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

To get started, clone the [Mythic](https://github.com/its-a-feature/Mythic/) repository, install it, and then pull down the [Merlin](https://github.com/MythicAgents/merlin) repository from the MythicAgents organization.

```text
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./start_mythic.sh
sudo ./install_agent_from_github.sh https://github.com/MythicAgents/merlin
sudo ./start_payload_types.sh merlin
```

## Known Limitations
This implementation of Merlin on the Mythic Framework is incomplete and is still in development. Here are some known limitations:

| Feature | Status | Notes |
| --- | --- | --- |
| MiniDump | Not Implemented
| Padding | Not Implemented
| File Chunking | Not Implemented
| Windows DLL | Not Implemented
