# intelAPTTwitter.py
import tweepy
import json
import re
from unshortenit import UnshortenIt


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
def extract_twitter_TI(apt):
    
    if apt not in APTS.keys():
        print("     [-] APT group not in database. If you want to list all the APT groups stored: \"python intelFarmer.py -l\"")
        # retrieve_groups() ?
        print("[+] Exiting...")
        return 0
    
    print(f"[+] Database read. Group found as {apt}.")
    print("[+] Connecting to Twitter API...")

    consumer_key = ""
    consumer_secret = ""
    access_token = ""
    access_token_secret = ""

    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    api = tweepy.API(auth)

    for alias in APTS[apt]:
        if removeSpaces(alias) not in APTS[apt]:
            APTS[apt].append(removeSpaces(alias))

    print(APTS[apt])

    # Search for aliases
    for alias in APTS[apt]:
        query = f'\"{alias}\"'
        search = api.search_tweets(query, result_type="recent", count=3)
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