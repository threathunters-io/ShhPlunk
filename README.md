# ShhPlunk

A Proof-of-Concept tool to mute the Splunk Forwarder on Linux.

## Usage

```bash
g++ poc.cpp -o shhplunk && ./shhplunk
```

## How it works

The `splunkd` process uses several threads to transmit data, with two of them being:

1. The heartbeat thread. It sends regular events the be able to determine whether a forwarder is still active.
2. A thread to send actual event data.

This PoC targets the second one, while keeping heartbeats intact. This way, `splunkd` no longer forwards any event-related data. To achieve this, the respective thread is being patched during runtime.

A full writeup can be found [here](https://bananamafia.dev/post/shhplunk/).