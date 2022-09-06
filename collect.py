#!/usr/bin/env python
# coding=utf-8
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pprint import pprint, pformat
import multiprocessing, threading
import base64
import datetime
import hashlib
import json
import logging
import traceback
import os
import random
import re
import shutil
import sys
import time
import functools
import csv
import uuid
import io
import atexit
import socket
import sqlite3
import itertools


"""
    @brief: say hello!
"""
print("                               ██                                 ██        ")
print("                        █████ ░░                                 ░██        ")
print(" ██████████   ██████   ██░░░██ ██  █████     █████   ██████      ░██  █████ ")
print("░░██░░██░░██ ░░░░░░██ ░██  ░██░██ ██░░░██   ██░░░██ ██░░░░██  ██████ ██░░░██")
print(" ░██ ░██ ░██  ███████ ░░██████░██░██  ░░   ░██  ░░ ░██   ░██ ██░░░██░███████")
print(" ░██ ░██ ░██ ██░░░░██  ░░░░░██░██░██   ██  ░██   ██░██   ░██░██  ░██░██░░░░ ")
print(" ███ ░██ ░██░░████████  █████ ░██░░█████   ░░█████ ░░██████ ░░██████░░██████")
print("░░░  ░░  ░░  ░░░░░░░░  ░░░░░  ░░  ░░░░░     ░░░░░   ░░░░░░   ░░░░░░  ░░░░░░ ")


"""
    @tag:   Common
    @brief: init common vars
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
real_path=os.getcwd()
scrpit_path=sys.path[0]
#os.chdir() # change current dir to script dir
today                = datetime.datetime.utcnow()
cn_today             = today + datetime.timedelta(hours = 8)
test_proxy_url       = "https://www.bing.com/"     if "test_proxy_url"          not in { **globals(), **locals() } else test_proxy_url
test_proxy_force_200 = False                       if "test_proxy_force_200"    not in { **globals(), **locals() } else test_proxy_force_200
anylog_repo_token    = "None"                      if "anylog_repo_token"       not in { **globals(), **locals() } else anylog_repo_token
anylog_timesleep     = 10                          if "anylog_timesleep"        not in { **globals(), **locals() } else anylog_timesleep
if_collect_info      = False                       if "if_collect_info"         not in { **globals(), **locals() } else if_collect_info
current_script_name  = os.path.basename(__file__)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:   Common
    @brief: logger init and give a global logger <Elogger>
    @get:   Elogger
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
class TerminalColour:
    """
    Terminal colour formatting codes
    """
    MAGENTA   = '\033[95m'
    BLUE      = '\033[94m'
    GREEN     = '\033[92m'
    YELLOW    = '\033[93m'
    PINK      = '\033[45m'
    RED       = '\033[91m'
    GREY      = '\033[0m'  # normal
    WHITE     = '\033[1m'  # bright white
    UNDERLINE = '\033[4m'

# logging.Formatter.converter = time.gmtime # force to use gmt time
logging.basicConfig(
    format  = f'<<%(asctime)s>>[%(levelname)8s] - %(message)s\t\t{TerminalColour.GREEN}PID-%(process)s:{TerminalColour.GREEN}%(name)s:%(funcName)s:%(pathname)s:%(lineno)d{TerminalColour.GREY}',
    datefmt =  '%Y-%m-%d %H:%M:%S %Z',
)

logging.addLevelName(logging.INFO     , "{}{}{}".format(TerminalColour.GREEN   , logging.getLevelName(logging.INFO)     , TerminalColour.GREY))
logging.addLevelName(logging.WARNING  , "{}{}{}".format(TerminalColour.YELLOW  , logging.getLevelName(logging.WARNING)  , TerminalColour.GREY))
logging.addLevelName(logging.ERROR    , "{}{}{}".format(TerminalColour.RED     , logging.getLevelName(logging.ERROR)    , TerminalColour.GREY))
logging.addLevelName(logging.CRITICAL , "{}{}{}".format(TerminalColour.MAGENTA , logging.getLevelName(logging.CRITICAL) , TerminalColour.GREY))
logging.addLevelName(logging.DEBUG    , "{}{}{}".format(TerminalColour.PINK    , logging.getLevelName(logging.DEBUG)    , TerminalColour.GREY))

log_level = "DEBUG" if "--debug" in sys.argv or os.getenv("LOG_LEVEL") == "debug" else "INFO"
Elogger   = logging.getLogger("<Eloco>")
Elogger.setLevel(log_level)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:   Common
    @brief: get the md5 of a file or folder
    @return: md5 string
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
def get_md5(file_path : str,
            logger    : logging.Logger = Elogger
            ) ->   str:

    try:
        if os.path.isfile(file_path):
            md5 = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk)
            return(md5.hexdigest()) # return files md5
        elif os.path.isdir(file_path):
            MD5File = "{}_tmp.md5".format(str(random.randint(0, 1000)).zfill(6))
            with open(MD5File, 'w') as outfile:
                md5_lst=[]
                for root, _, files in os.walk(file_path):
                    for file in files:
                        filefullpath = os.path.join(root, file)
                        md5 = get_md5(file_path=filefullpath)
                        md5_lst.append([md5,file])
                md5_lst=sorted(md5_lst)
                for md5 in md5_lst:
                    outfile.write(md5[0]+md5[1])
            val = get_md5(MD5File)
            os.remove(MD5File)
            return(val) # return folders md5
    except Exception as e:
        logger.error(e)
        logger.debug(traceback.format_exc())
        return(False)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:   Common
    @brief: make bit look good
    @return: bit string
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
def bsize(bsize: int) -> str:
    if bsize < 1024:  #比特
        bsize    = str(round(bsize, 2)) + ' B' #字节
    elif bsize >= 1024 and bsize < 1024 * 1024:
        bsize   = str(round(bsize / 1024, 2)) + ' KB' #千字节
    elif bsize >= 1024 * 1024 and bsize < 1024 * 1024 * 1024:
        bsize   = str(round(bsize / 1024 / 1024, 2)) + ' MB' #兆字节
    elif bsize >= 1024 * 1024 * 1024 and bsize < 1024 * 1024 * 1024 * 1024:
        bsize   = str(round(bsize / 1024 / 1024 / 1024, 2)) + ' GB' #千兆字节
    elif bsize >= 1024 * 1024 * 1024 * 1024 and bsize < 1024 * 1024 * 1024 * 1024 * 1024:
        bsize   = str(round(bsize / 1024 / 1024 / 1024 / 1024, 2)) + ' TB' #太字节
    elif bsize >= 1024 * 1024 * 1024 * 1024 * 1024 and bsize < 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
        bsize   = str(round(bsize / 1024 / 1024 / 1024 / 1024 / 1024, 2)) + ' PB' #拍字节
    elif bsize >= 1024 * 1024 * 1024 * 1024 * 1024 * 1024 and bsize < 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
        bsize   = str(round(bsize / 1024 / 1024 / 1024 / 1024 / 1024 /1024, 2)) + ' EB' #艾字节
    return(bsize)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:   Common
    @brief: determine if base64
    @return: bool
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
def isBase64(sb) -> bool:
    try:
       if isinstance(sb, str):
               # If there's any unicode here, an exception will be thrown and the function will return false
               sb_bytes = bytes(sb, 'ascii')
       elif isinstance(sb, bytes):
               sb_bytes = sb
       else:
               raise ValueError("Argument must be string or bytes")
       return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:   Common
    @brief: support anylog project
    @return: success or failure
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
def send_log_github(repo     : str = "CECNdata/anylog"                    ,
                    filename : str = "misc/"+current_script_name          ,
                    stime    : str = cn_today.strftime("%Y%m%d%H%M%ST+8") ,
                    token    : str = anylog_repo_token                    ,
                    content  : str = "default upload message"             ,
                    logger   : logging.Logger = Elogger
                    ) -> bool:
    try:
        if token == "None":
            logger.error(f"need gihtub repo <{repo}> token (at least gist write)")
            return(False)
        else:
            content=base64.b64encode(content.encode("utf-8")).decode('utf-8')
            headers = {
                'User-Agent'    : 'HTTPie/1.0.3'            ,
                'Accept'        : 'application/json, */*'   ,
                'Connection'    : 'keep-alive'              ,
                'Content-Type'  : 'application/json'        ,
                'Authorization' : 'token '+token            ,
            }
            data    = {
                "message"       : "upload log"                                    ,
                "committer"     : { "name"  : "cecndata"                          ,
                                    "email" : "CECNdata@users.noreply.github.com" , } ,
                "content"       : content
            }
            repo     = f"https://api.github.com/repos/{repo}/contents/"
            filename = f"{filename}.{stime}.log"
            r        = requests.put(repo+filename, headers = headers, data = json.dumps(data))

            if str(r.status_code)[:2] == "20":
                logger.info(f"upload log to github <{repo}> success with {r.status_code}")
                return(True)
            else:
                logger.debug(f"[Anylog] github-api PUT return: \n{r.text}")
                logger.error(f"upload log to github <{repo}> failed with {r.status_code}")
                return(False)
    except Exception as e:
        logger.error(e)
        logger.debug(traceback.format_exc())
        return(False)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:    PDP && CPY
    @brief:  run <anylog> at the end of a program
    @return: success or failure
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
@atexit.register
def bpa_send_any_log(repo       : str            = "CECNdata/anylog"                    ,
                     token      : str            = anylog_repo_token                    ,
                     stime      : str            = cn_today.strftime("%Y%m%d%H%M%ST+8") ,
                     time_sleep : int            = anylog_timesleep                     ,
                     logger     : logging.Logger = Elogger
                    ) -> bool   :
    os.chdir(sys.path[0]) # change current dir to script dir
    try:
        if token == "None":
            logger.error(f"need gihtub repo <{repo}> token (at least gist write)")
            return(False)
        else:
            # https://stackoverflow.com/questions/69448044/convert-log-files-to-base64-and-upload-it-using-curl-to-github
            clean_escape           = """sed "s/{slash}x1b{slash}[[0-9;]*m//g" | sed -r "s/[{slash}x08{slash}x7c{slash}x2f{slash}x2d{slash}x5c{slash}x2d]{3,}//g" """ 
            base_command           = f"""cat {{log_path}} | {clean_escape} |  base64 --wrap=0   | jq --raw-input --compact-output "{{{{slash}}"message{{slash}}": {{slash}}"Log files{{slash}}", {{slash}}"content{{slash}}": . }}" | curl --request PUT --user ":{token}"  --header "Accept: application/vnd.github.v3+json" --header "Content-Type: application/json" --data-binary @- --url "https://api.github.com/repos/{repo}/contents/{{atp_name}}/{{filename}}" """
            final_commands         = []
            if current_script_name == "pdp.py":
                atp_name = os.path.basename(os.path.abspath(os.path.join(os.getcwd(), "../.."))).strip()
                head_filename="PDP"
                log_path_list      = [
                    f"{real_path}/../../cdp_log.txt" ,
                ]
            elif current_script_name == "parser.py":
                atp_name               = os.path.basename(real_path).strip()
                head_filename="CPY"
                log_path_list      = [
                    f"{real_path}/parser_log.txt"           ,
                    f"{real_path}/cdp_log.txt"              ,
                    #f"{real_path}/{atp_name}_init_log.txt" ,
                ]
            else:
                logger.debug(f"current script name is {current_script_name} not support <bpa_send_any_log>")
                return(False)

            # obtain final command list
            for log in log_path_list:
                if os.path.exists(log):
                    filename     = f"{atp_name}_{head_filename}_{os.path.basename(log)}_{stime}.log"
                    final_commands.append(base_command.replace("{filename}",filename).replace("{log_path}",log).replace("{atp_name}",atp_name))
                else:
                    logger.warning(f"logfile <{log}> not exist")

            # run anylog when the current script over
            pid=os.fork()
            if pid==0: # new process
                for command in final_commands:
                    command       = command.replace('{slash}',chr(92))
                    final_command = f"""nohup bash -c 'sleep {time_sleep}s;{command}' &> /dev/null & """
                    logger.debug(f"""run nohup command <{final_command}>""")
                    os.system(final_command)
            return(True)
    except Exception as e:
        logger.error(e)
        logger.debug(traceback.format_exc())
        return(False)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:    PDP
    @brief:  calc md5 from ./downloads, and remove the same md5 and record the new to index.txt
    @return: success or failure
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
def bpa_index_md5_check(logger  : logging.Logger = Elogger
                       ) -> bool:
    try:
        index_path = "./index.txt"
        md5_json = json.loads(open(index_path).read()
                              ) if os.path.exists(index_path) else {}

        def walk_file_index(md5_json: dict = md5_json) -> dict:
            L = []
            summary = {}
            summary["same"] = {}
            summary["downloaded"] = {}
            for root, _, files in os.walk("downloads"):
                for file in files:
                    file_dir = os.path.join(root, file)
                    md5 = get_md5(file_path=file_dir)
                    if file in md5_json:
                        if md5 == md5_json[file]:
                            summary["same"][file] = 0
                            os.remove(file_dir)
                            logger.info(f"[MD5]:\t<{file_dir}> has same md5, now del")
                        else:
                            summary["downloaded"][file] = 0
                            md5_json[file] = md5
                    else:
                        md5_json[file] = md5
                        summary["downloaded"][file] = 0
            with open("summary.txt", "w") as f:
                f.write(json.dumps(summary))
            return(md5_json)

        # main function here
        if os.path.exists(index_path):
            md5_json = walk_file_index()
            with open(index_path, "w") as f:
                f.write(json.dumps(md5_json))
            return(True)
        else:
            logger.warning(f"<{index_path}> not exists,{{index_md5_check}} failure")
            return(False)
    except Exception as e:
        logger.error(e)
        logger.debug(traceback.format_exc())
        return(False)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:    PDP
    @brief:  init request proxy from options.json
    @return: success or failure
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
def bpa_init_request_proxy(test_proxy_url               : str = test_proxy_url        ,
                           test_proxy_force_200         : bool = test_proxy_force_200 ,
                           test_timeout                 : int = 30                    ,
                           logger                       : logging.Logger = Elogger
                          ) -> requests.sessions.Session: 

    s = requests.Session()
    try:
        s.verify = False  # disable ssl verify
        atp_name = os.path.basename(os.path.abspath(os.path.join(os.getcwd(), "../.."))).strip()
        # reading the proxy settings from {atp}.json
        atp_json_path = f"../../{atp_name}.json"
        if os.path.exists(atp_json_path):
            atp_config               = json.loads(open(atp_json_path, "r").read())
            proxy_config             = atp_config["proxy"].strip()
            if "NO"                 != proxy_config and "" != proxy_config:
                proxy_config         = atp_config["proxy"].split("--proxy-auth=")
                if len(proxy_config) == 2:  # add auth to proxy_string
                    auth_string      = proxy_config[1].strip()
                    proxy_config[0]  = auth_string+"@"+proxy_config[0]
                proxy_string         = "http://" + \
                    proxy_config[0] if "http://" not in proxy_config[0] else proxy_config[0]
                proxy_string = proxy_string.strip()
                logger.info(f"[proxy] use proxy: `{proxy_string}`")
                s.proxies = {
                    "http"  : proxy_string,
                    "https" : proxy_string
                }
                test_proxy = s.get(test_proxy_url, timeout=test_timeout)
                logger.info(f"[proxy] `{test_proxy_url}` proxy code: {str(test_proxy.status_code)}")
                if test_proxy_force_200:
                    test_proxy.raise_for_status()
    except Exception as e:
        logger.error(e)
        logger.debug(traceback.format_exc())
        s.proxies = None
        s.auth    = None
    s.verify      = False  # disable ssl verify
    return(s)
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑



"""
    @brief:  collect info to anylog
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
try:
    if current_script_name   == "pdp.py":
        filename             = os.path.basename(os.path.abspath(os.path.join(os.getcwd(), "../.."))).strip()+f"_{current_script_name}"
    elif current_script_name == "parser.py":
        filename             = os.path.basename(real_path).strip()+f"_{current_script_name}"
    else:
        filename             = current_script_name

    if if_collect_info:
        def get_internal_ip() -> str: # get internal ip
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip=s.getsockname()[0]
            s.close()
            return(ip)
        internal_ip = get_internal_ip()
        external_ip = requests.get("https://api.ipify.org").text
        content=""
        content+=f"internal running ip: {internal_ip}\n"
        content+=f"external running ip: {external_ip}\n"
        send_log_github(content=content,filename="misc/"+filename)
except:
    pass
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


"""
    @tag:    END
"""
#↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
os.chdir(real_path) # change back to default path
print("`loading eloco magic-code success`")
#↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
