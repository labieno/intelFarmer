import feedparser
import os
import json
from json.decoder import JSONDecodeError
from time import gmtime
from datetime import datetime, timedelta, timezone, date


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

rss_feed_list = [
    ['https://grahamcluley.com/feed/', 'Graham Cluley'],
    ['https://www.mandiant.com/resources/blog/rss.xml','Mandiant'],
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
    ['https://securityintelligence.com/category/x-force/feed/','IBM X-Force'],
    ['https://www.netskope.com/blog/category/netskope-threat-labs/feed','Netskope Cloud Security'],
    #['https://www.mcafee.com/blogs/tag/advanced-threat-research/feed','McAfee'],                           #not updated
    #['https://www.paloaltonetworks.com/blog/category/threat-research/feed/','Palo Alto Networks'],         #not updated
    #['https://cybersecurity.att.com/site/blog-all-rss', 'ATT'],                                             #ocurre un problema con este feed
    ["https://www.cisa.gov/uscert/ncas/alerts.xml", "US-CERT CISA"],
    ["https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "NCSC"],
    ["https://www.cisecurity.org/feed/advisories", "Center of Internet Security"],
    ['https://blog.cyble.com/feed/','Cyble'],
    ['https://securityaffairs.com/feed', 'Security affairs'],
    ['https://www.runzero.com/blog/index.xml','runZero'],
    ['https://blog.thinkst.com/feed','THINKST'],
    ['https://www.ransomware.live/rss.xml', 'Ransomware.live']
]

def update_database_json():
    try:
        os.mkdir("logs")
    except OSError:
        pass # Most likely simply means the folder already exists
    for source in rss_feed_list:
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
                    json.dump(s, outfile, indent=4)
                    print("     [+] Done")
                        
            else:
                print("========================================", source[1], "========================================")
                print(f"        [+] {filename} found! Searching for new reports in current month:")
                with open(filename, 'r') as infile:
                    data = json.load(infile)
                    list_articles = []
                    try:
                        now = gmtime()
                        NewsFeed = feedparser.parse(source[0])
                        entries = NewsFeed.entries
                        new_articles = 0
                        for a in data['articles']:
                            
                            try:
                                if a['published_parsed'][0] == now[0]:
                                    list_articles.append(a['title'])
                            except TypeError: # Mandiant
                                if f"{a['time']['datetime'][0:4]}" == f"{datetime.now():%Y}":
                                    list_articles.append(a['title'])
                        for entry in entries:
                            try:
                                if (entry.published_parsed[0],entry.published_parsed[1],entry.published_parsed[2]) == (now[0],now[1],now[2]): # PRINT CURRENT DAY
                                    print("\033[0;34m", entry['published'], "==========", entry['title'], "==========>", entry['link'], "\033[0m")
                                
                                #NEW ARTICLES
                                if (entry.published_parsed[0],entry.published_parsed[1]) == (now[0],now[1]) and entry['title'] not in list_articles: # YEAR MONTH
                                    print("\033[0;31m", entry['published'], "==========", entry['title'], "==========>", entry['link'], "\033[0m")
                                    new_articles += 1
                                    data['articles'].append(entry)
                            except:
                                if (f"{entry.time['datetime'][0:4]} {entry.time['datetime'][5:7]}" == f"{datetime.now():%Y %m}") == (f"{datetime.now():%Y %m %d}"): # PRINT CURRENT DAY
                                    print("\033[0;34m", entry['published'], "==========", entry['title'], "==========>", entry['link'], "\033[0m")
                                
                                #NEW ARTICLES
                                if (f"{entry.time['datetime'][0:4]} {entry.time['datetime'][5:7]}" == f"{datetime.now():%Y %m}") and entry['title'] not in list_articles: # YEAR MONTH
                                    print("\033[0;31m", entry['published'], "==========", entry['title'], "==========>", entry['link'], "\033[0m")
                                    new_articles += 1
                                    data['articles'].append(entry)
                        if new_articles:
                            print(f"\033[0;31m        [+] {new_articles} new articles added to", filename, "\033[0m")
                            with open(filename, "w") as outfile:  # añadir al json
                                data['articles'][0]['time']
                                json.dump(data, outfile, indent=4)
                        else:
                            print("        [+] No new articles added to", filename)
                    except Exception as eee:
                        print(eee)
                        raise

        except Exception as e:
            print(e)
            raise


def get_last_n_days_feed(d):
    for source in rss_feed_list:
            feed = feedparser.parse(source[0])
            print("========================================", source[1], "========================================")
            for entry in feed.entries[:10]:
                try:
                    published_date = datetime.fromtimestamp(datetime(*entry.published_parsed[:6]).timestamp(), tz=timezone.utc)

                    if datetime.now(timezone.utc) - published_date <= timedelta(days=d):
                        print("\033[0;34m", entry.published, "==========", entry.title, "==========>", entry.link, "\033[0m")
                except:
                    try:
                        published_date = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %z")
                    except ValueError:
                        try:
                            published_date = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %Z")
                        except ValueError:
                            try:
                                published_date = datetime.strptime(entry.published, "%Y-%m-%dT%H:%M:%S.%f%z")
                            except ValueError:
                                published_date = datetime.strptime(entry.published, "%a, %m/%d/%Y - %H:%M")

                    published_date = published_date.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - published_date <= timedelta(days=d):
                        print("\033[0;34m", entry.published, "==========", entry.title, "==========>", entry.link, "\033[0m")

def check_source(s):
    url = ''
    for source in rss_feed_list:
        if s == source[1]:
            url = source[0]
            break
    if url != '':
        feed = feedparser.parse(url)
        print("========================================", source[1], "========================================")
        for entry in feed.entries[:10]:
            try:
                # Obtenemos la fecha de publicación a partir del atributo published_parsed
                published_date = datetime.fromtimestamp(datetime(*entry.published_parsed[:6]).timestamp(), tz=timezone.utc)

                if datetime.now(timezone.utc) - published_date <= timedelta(days=7):
                    print("\033[0;34m", entry.published, "==========", entry.title, "==========>", entry.link, "\033[0m")
            except:
                try:
                    published_date = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %z")
                except ValueError:
                    try:
                        published_date = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %Z")
                    except ValueError:
                        try:
                            published_date = datetime.strptime(entry.published, "%Y-%m-%dT%H:%M:%S.%f%z")
                        except ValueError:
                            published_date = datetime.strptime(entry.published, "%a, %m/%d/%Y - %H:%M")

                published_date = published_date.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) - published_date <= timedelta(days=7):
                    print("\033[0;34m", entry.published, "==========", entry.title, "==========>", entry.link, "\033[0m")
    else:
        print(f"[-] {s} not in feed list")