# breach_monitor
[![GitHub release](http://img.shields.io/github/release/jakewarren/breach_monitor.svg?style=flat-square)](https://github.com/jakewarren/breach_monitor/releases])
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/jakewarren/breach_monitor/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jakewarren/breach_monitor)](https://goreportcard.com/report/github.com/jakewarren/breach_monitor)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)
> queries hacked-emails.com and haveibeenpwned.com
## Install
### Option 1: Binary

Download the latest release from [https://github.com/jakewarren/breach_monitor/releases/latest](https://github.com/jakewarren/breach_monitor/releases/latest)

### Option 2: From source

```
go get github.com/jakewarren/breach_monitor
```

## Usage
```
❯ breach_monitor -h
usage: breach_monitor [<flags>] <email>

queries hacked-emails.com and haveibeenpwned.com.

Optional flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
  -d, --debug                    print debug info
  -f, --filter-date=FILTER-DATE  only print breaches released after specified date
  -s, --silent                   suppress response message, only display results
  -V, --version                  Show application version.

Args:
  <email>  the email address to lookup.
```
## Changes

All notable changes to this project will be documented in the [changelog].

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

## License

MIT © 2018 Jake Warren

[changelog]: https://github.com/jakewarren/breach_monitor/blob/master/CHANGELOG.md
