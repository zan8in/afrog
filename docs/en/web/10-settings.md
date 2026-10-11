<!--
title: Settings
slug: /docs/web/settings
lang: en
summary: Web console settings: account and security, notifications, OOB out-of-band detection, AI assist, and service information.
status: published
source: new
last_reviewed: 2026-10-10
-->

## What is in Settings

| Section | Content |
| --- | --- |
| Account | Login and security notes (single-password login) |
| Notifications | Push channels and logs for hit/settling messages |
| OOB | Reverse-connection credentials for out-of-band detection |
| AI assist | Model connection configuration and connectivity test |
| Service info | Version, instance information, and so on |

## Account and security

The console signs in with a **single access password**; the password is randomly generated on every start and printed to the terminal. There is no built-in HTTPS, so if you expose it publicly put it behind a reverse proxy and add TLS and access control yourself. For the security boundary see [Overview](./01-overview.md).

## Notifications

You can configure hit and task-settling messages to be pushed to team channels (such as DingTalk / WeCom), view the send log, and retry failed sends. Notifications are de-duplicated and rate-limited per task to avoid spam.

> Notifications are a member feature.

## OOB out-of-band detection

OOB (out-of-band) is used to verify **blind vulnerabilities**: first make the target actively visit an external address, then query the OOB platform for whether a visit was recorded. Fill in the reverse-connection configuration (the `reverse` section) in Settings; saving writes back to `afrog-config.yaml` and takes effect the next time a scan subprocess starts.

For how OOB is written in a PoC see [OOB out-of-band detection](../poc/06-oob.md).

## AI assist

Fill in the model service's address, key and model name; saving takes effect immediately (no restart). Saving itself **does not call the model**; once filled in you can click **Test connection** to send one tiny request and confirm the address / key / model name actually work. For the quota and the three capabilities see [AI Assist](./09-ai.md).

## Service information

Shows the current service version, instance identifier and other runtime information, to help confirm the deployment and troubleshoot environment issues.

> Some settings are **written back to the config file** (such as the `reverse` section for OOB and the `ai` section for AI); for the field dictionary see the [configuration file reference](../user-guide/05-configuration.md).

> **← Previous:** [AI Assist](./09-ai.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md)
