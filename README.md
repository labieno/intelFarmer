# intelFarmer

intelFarmer is a tool to keep up with the daily release of Threat Intelligence reports. It monitors specified feeds from public sources, highlights the new ones and store them in a database.

Aditionally, it allows to add Twitter API keys to search for tweets about certain APT groups.

## Usage
```
python .\intelFarmer.py -h
usage: intelFarmer.py [-h] [-v] (-g APT_group | -l | -i)

Get threat intel from known feeds (and store it). Get threat intel info about APT groups from tweets (add API keys in intelAPTTwitter.py)

options:
  -h, --help            show this help message and exit
  -v, --version         display current version
  -g APT_group, --group APT_group
                        Search for info of an APT group in recent tweets (case sensitive). DO NOT FORGET TO ADD API KEYS
  -l, --list            List all APT groups in database
  -i                    Search for new threat intel reports and update database (first run is very verbose)

intelFarmer 0.0 || More info at https://github.com/labieno/intelFarmer
```

### Threat Intelligence feed (-i)

#### First run - very verbose
It will create a 'logs' folder an a .json for each feed and keep up to date with them.
![creatinglogs](https://user-images.githubusercontent.com/62944884/225639399-e39c8c54-4a15-4ed4-962a-cb80208f4bd8.png)


#### Later runs
It will update the .json files (new stored reports in red) and highlights (blue) the reports released at current day.
![updating logs](https://user-images.githubusercontent.com/62944884/225639448-53a98374-2e9b-47f2-93fc-6c1784897792.png)


* You can update feed list at 'src/rss_feed.py'

### APT group aliases tweet search (-g/--group APT_group)
Search for 



## To-Do
* Add telegram sources
* Add dark web sources
* Add bot functionality

## Ideas

## Changelog
### 0.0 - 2023-03-16
#### Initial release
