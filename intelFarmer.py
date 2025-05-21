# intelFeed.py
import argparse
import os
import re
from src.apt_mitre import *
from src.rss_feed import *

def main():
    parser = argparse.ArgumentParser(#prog = 'intelFarmer',
                                    #usage = '%(prog)s [options] APT_group',
                                    description = 'Get threat intel from known feeds (and store it). Get threat intel info about APT groups from tweets (add API keys in intelAPTTwitter.py)',
                                    epilog="intelFarmer 0.1 || More info at https://github.com/labieno/intelFarmer")

    parser.version = 'intelFarmer 0.1'
    parser.add_argument('-v',
                        '--version',
                        action='version',
                        help='display current version')
    
    # For exclusivity
    group = parser.add_mutually_exclusive_group(required=True)

    # Arguments
    """
    group.add_argument('-g',
                        metavar=("APT_group", "number_of_tweets"),
                        type=str,
                        help="Search for info of an APT group in recent tweets (case sensitive). DO NOT FORGET TO ADD API KEYS",
                        action='store',
                        nargs=2)"
    """
    
    group.add_argument('-i',
                        help='Search for new threat intel reports and update database (first run is very verbose)',
                        action='store_true')
    
    group.add_argument('-d',
                        metavar='days',
                        help="Search for last 10 threat intel reports of last specified number of days",
                        action='store',
                        nargs=1)

    group.add_argument('-s',
                        metavar='source',
                        type=str,
                        help="Check a source - last week reports",
                        action='store',
                        nargs=1)

    group.add_argument('-l',
                        '--list',
                        help="List all APT groups in database",
                        action='store_true',)
    
    group.add_argument('-g',
                        metavar=("APT_group"),
                        type=str,
                        help="Search for relevant information of a group stored in MITRE",
                        action='store',
                        nargs=1)

    group.add_argument('-group',
                        metavar="APT_group",
                        type=str,
                        help="Search reports of an APT group in recent publications (case sensitive)",
                        action='store',
                        nargs=1)
    
    group.add_argument('-vx',
                        help="Extract all VX-Undergroun APT reports",
                        action='store_true')
    




    # Execute the parse_args() method to look up the arguments an process them
    args = parser.parse_args()

    # Execute tool
    if args.i: # TO RESET DATABASE, ERASE .jsons in "logs" folder
        import src.rss_feed as rss_feed
        update_database_json()
    elif args.d:
        import src.rss_feed as rss_feed
        get_last_n_days_feed(int(args.d[0]))
    elif args.s:
        import src.rss_feed as rss_feed
        check_source(args.s[0])


    elif args.list:
        import src.rss_feed as rss_feed
        retrieve_groups()
    elif args.g:
        import src.rss_feed as rss_feed
        get_group_info(args.g[0])
        #import src.intelAPTTwitter as intelAPTTwitter
        #intelAPTTwitter.extract_twitter_TI(args.g[0],int(args.g[1]))
    elif args.group:
        import src.rss_feed as rss_feed
        extract_APT_reports(args.group[0])
    elif args.vx:
        import src.rss_feed as rss_feed
        extract_vxUndergroundReports()


    





if __name__ == "__main__":
    main()