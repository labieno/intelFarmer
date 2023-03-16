import feedparser
import os
import json
from json.decoder import JSONDecodeError
from time import gmtime

"""from mitreattack.stix20 import MitreAttackData

mitre_attack_data = MitreAttackData("enterprise-attack.json")
groups = mitre_attack_data.get_groups()
print(len(groups))
#print(groups[0]['aliases'])

APTS = {}
for group in groups:
    try:
        APTS[group['name']] = group['aliases']
    except:
        pass
print(APTS)
"""

private_rss_feed_list = [
    ['https://grahamcluley.com/feed/', 'Graham Cluley'],
    ['https://lab52.io/blog/feed/', 'lab52'],
    ['https://threatpost.com/feed/', 'Threatpost'],
    ['https://krebsonsecurity.com/feed/', 'Krebs on Security'],
    ['https://www.darkreading.com/rss.xml', 'Dark Reading'],
    ['http://feeds.feedburner.com/eset/blog', 'We Live Security'],
    ['https://davinciforensics.co.za/cybersecurity/feed/', 'DaVinci Forensics'],
    ['https://blogs.cisco.com/security/feed', 'Cisco'],
    ['https://www.infosecurity-magazine.com/rss/news/', 'Information Security Magazine'],
    ['http://feeds.feedburner.com/GoogleOnlineSecurityBlog', 'Google'],
    ['http://feeds.trendmicro.com/TrendMicroResearch', 'Trend Micro'],
    ['https://www.bleepingcomputer.com/feed/', 'Bleeping Computer'],
    ['https://www.proofpoint.com/us/rss.xml', 'Proof Point'],
    ['http://feeds.feedburner.com/TheHackersNews?format=xml', 'Hacker News'],
    ['https://www.schneier.com/feed/atom/', 'Schneier on Security'],
    ['https://www.binarydefense.com/feed/', 'Binary Defense'],
    ['https://securelist.com/feed/', 'Securelist'],
    ['https://research.checkpoint.com/feed/', 'Checkpoint Research'],
    ['https://www.virusbulletin.com/rss', 'VirusBulletin'],
    ['https://modexp.wordpress.com/feed/', 'Modexp'],
    ['https://www.tiraniddo.dev/feeds/posts/default', 'James Forshaw'],
    ['https://blog.xpnsec.com/rss.xml', 'Adam Chester'],
    ['https://msrc-blog.microsoft.com/feed/', 'Microsoft Security'],
    ['https://www.recordedfuture.com/feed', 'Recorded Future'],
    ['https://www.sentinelone.com/feed/', 'SentinelOne'],
    ['https://redcanary.com/feed/', 'RedCanary'],
    #['https://cybersecurity.att.com/site/blog-all-rss', 'ATT'] #ocurre un problema con este feed: no tiene 'published' ni 'published_parsed'
]

def update_database_json():
    try:
        os.mkdir("logs")
    except OSError:
        pass # Most likely simply means the folder already exists
    for source in private_rss_feed_list:
        filename = f"logs/{source[1]}.json"
        try:
            if (not os.path.exists(filename)) or (os.path.getsize(filename) <= 2):
                with open(filename, "w") as outfile:
                    print("========================================", source[1], "========================================")
                    print(f"\033[0;31m        [+] Creating {filename}...\033[0m")
                    NewsFeed = feedparser.parse(source[0])
                    entries = NewsFeed.entries
                    s = {'articles':[]}
                    for entry in entries:
                        s['articles'].append(entry)
                        try:
                            print(entry['published'], "==========", entry['title'], "==========>", entry['link'])
                        except Exception as err:
                            #print(err)
                            pass
                    json.dump(s, outfile)
                    print("     [+] Done")
                        
            else:
                print("========================================", source[1], "========================================")
                print(f"        [+] {filename} found! Searching for new reports in current month:")
                with open(filename, 'r') as infile:
                    data = json.load(infile)
                    list_articles = []
                    try:
                        now = gmtime()
                        for a in data['articles']:
                            if a['published_parsed'][0] == now[0]:
                                list_articles.append(a['title'])
                        
                        # Check for new articles
                        NewsFeed = feedparser.parse(source[0])
                        entries = NewsFeed.entries
                        new_articles = 0
                        for entry in entries:
                            if (entry.published_parsed[0],entry.published_parsed[1],entry.published_parsed[2]) == (now[0],now[1],now[2]): # PRINT CURRENT DAY
                                print("\033[0;34m", entry['published'], "==========", entry['title'], "==========>", entry['link'], "\033[0m")
                            
                            #NEW ARTICLES
                            if (entry.published_parsed[0],entry.published_parsed[1]) == (now[0],now[1]) and entry['title'] not in list_articles: # YEAR MONTH
                                print("\033[0;31m", entry['published'], "==========", entry['title'], "==========>", entry['link'], "\033[0m")
                                new_articles += 1
                                data['articles'].append(entry)
                        if new_articles:
                            print(f"\033[0;31m        [+] {new_articles} new articles added to", filename, "\033[0m")
                            with open(filename, "w") as outfile:  # añadir al json
                                json.dump(data, outfile)
                        else:
                            print("        [+] No new articles added to", filename)
                    except Exception as eee:
                        print(eee)
                        raise

        except Exception as e:
            print(e)
            raise
