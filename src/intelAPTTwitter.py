# intelAPTTwitter.py
import tweepy
import re
from unshortenit import UnshortenIt
import configparser
import os



def removeSpaces(string):
    string = string.replace(' ','')
    return string

# Auxiliary functions
def convert_case(match_obj):
    unshortener = UnshortenIt()
    return match_obj.group(1) + " -> " + unshortener.unshorten(match_obj.group(1))

# Import MITRE and get groups
print("[+] Connecting to MITRE database...")
from mitreattack.stix20 import MitreAttackData

# https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
mitre_attack_data = MitreAttackData("enterprise-attack.json")
groups = mitre_attack_data.get_groups()

APTS = {}
for group in groups:
    try:
        APTS[group['name']] = group['aliases']
    except:
        pass

# List APT groups
def retrieve_groups():
    print("[+] Listing APT groups stored in database...")
    for group in APTS.keys():
        print(f"-    {group}")


# Main function: extract tweets that contains an alias of the APT
def extract_twitter_TI(apt, days):
    
    if apt not in APTS.keys():
        print("     [-] APT group not in database. If you want to list all the APT groups stored: \"python intelFarmer.py -l\"")
        # retrieve_groups() ?
        print("[+] Exiting...")
        return 0
    
    print(f"[+] Database read. Group found as {apt}.")
    print("[+] Connecting to Twitter API...")

    config = configparser.ConfigParser()
    ini_path = os.path.join(os.getcwd(),'config.ini')
    config.read(ini_path)
    consumer_key = config.get("Twitter", "consumer_key", raw=True)
    consumer_secret = config.get("Twitter", "consumer_secret", raw=True)
    access_token = config.get("Twitter", "access_token", raw=True)
    access_token_secret = config.get("Twitter", "access_token_secret", raw=True)

    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    api = tweepy.API(auth)

    for alias in APTS[apt]:
        if removeSpaces(alias) not in APTS[apt]:
            APTS[apt].append(removeSpaces(alias))

    print(f"[+] Aliases of {apt}", APTS[apt])

    # Search for aliases
    for alias in APTS[apt]:
        query = f'\"{alias}\"'
        search = api.search_tweets(query, result_type="recent", count=days)
        print(f"\033[1;32m ======================================================== {alias}")
        for t in search:
            print(f"\033[1;31m{t.created_at}") # print date

            tweet = api.get_status(t.id, tweet_mode = "extended") # extended mode

            if hasattr(tweet, "retweeted_status"): # is it a RETWEET?
                print(tweet.full_text[:tweet.full_text.find(':')])
                print(re.sub("(https://t.co[^\s]+)", convert_case, tweet.retweeted_status.full_text))      
            else:
                print(re.sub("(https://t.co[^\s]+)", convert_case, tweet.full_text))
            
            print("                 User: ", tweet.user.screen_name)
            print("                 Followers:", tweet.user.followers_count)
            print("========================================================")