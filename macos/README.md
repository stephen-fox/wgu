# macOS launchd agent

## Install

Copy script into:
`/Users/<your-user>/Library/LaunchAgents/com.gitlab.stephen-fox.wgu.plist`

## Enable

```sh
launchctl load -w ~/Library/LaunchAgents/com.gitlab.stephen-fox.wgu.plist
```

## Disable

```sh
launchctl unload -w ~/Library/LaunchAgents/com.gitlab.stephen-fox.wgu.plist
```
