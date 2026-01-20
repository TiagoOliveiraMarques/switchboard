# Switchboard (v1) — Design Summary

## Problem statement

Teams integrating with third-party services that use webhooks struggle to test end-to-end flows in local development.
Webhook providers typically require a **publicly reachable URL**, while developers’ apps run on machines not exposed to
the internet. In a multi-developer team, this becomes worse: developers tend to rely on pre-prod environments to test
and debug their integrations, resulting in a slow iteration cycle.

Switchboard aims to fix this by enabling developers to work with third-party webhooks directly from their local
development environments.

## Architecture

### Agent

The agent is an application running on the developer machine. It acts as a local proxy from the developer's app and the
remote proxy in the cloud. It is responsible for establishing a 2-way communication channel (the tunnel) with the
proxy, so that the developer's laptop can receive traffic without having to deal with opening ports and firewall rules.

### Proxy

The proxy is the public-facing Switchboard service. It has a stable webhook ingress endpoint that third-party providers
post to, as well as receiving requests from the agents installed in the developers' machines. It is responsible for
matching outbound requests with inbound notifications, so that third-party notifications are routed to the correct
developer machine.

### Tunnel

A persistent connection from an agent to the proxy used for two-way delivery: proxy \(\rightarrow\) agent webhook
delivery and agent \(\rightarrow\) proxy response propagation.

### Webhook sender

The third-party system that issues webhook HTTP requests (e.g., GitHub, Stripe, Slack) to the proxy's public ingress
endpoint.

### Local app

The developer's application running locally. It makes outbound requests (captured by the agent) and receives inbound
webhook HTTP requests forwarded by the agent.

### Detailed specs

- `architecture/agent-proxy-authentication.md` — Agent \(\rightarrow\) Proxy authentication
- `architecture/tunnel-protocol.md` — Tunnel protocol
- `architecture/proxy-routing.md` — Proxy routing
