# macOS launchd agent

## Install

Copy script into:
`/Users/<your-user>/LaunchAgents/com.gitlab.stephen-fox.wgu.plist`

## Enable

```sh
launchctl load -w ~/LaunchAgents/com.gitlab.stephen-fox.wgu.plist
```

## Disable

```sh
launchctl unload -w com.gitlab.stephen-fox.wgu.plist
```
