+++
title = "killdate"
chapter = false
weight = 100
hidden = false
+++

## Summary

The date, as a Unix epoch timestamp, that the agent should quit running.
Visit: <https://www.epochconverter.com/>

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### date

- Description: The date, as a Unix epoch timestamp, that the agent should quit running
- Required Value: True
- Default Value: None

## Usage

```
killdate <epoch timestamp>
```

## MITRE ATT&CK Mapping

None

## Detailed Summary

The `killdate` command allows an Operator to dynamically change the date and time at which the agent will quit working.
This is useful when an operation timeline has been extended.
