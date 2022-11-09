import decimal
import ijson
import json
import os
import sys

def parse(parser):
    prefix, event, value = next(parser)

    if event == "null":
        return value
    elif event == "boolean":
        return value
    elif event == "number":
        if (isinstance(value, decimal.Decimal)):
            return float(value)
        else:
            return value
    elif event == "string":
        return value
    elif event == "start_array":
        return parse_list(parser)
    elif event == "start_map":
        return parse_dict(parser)
    else:
        raise ValueError(f"Unknown event '{event}' with prefix '{prefix}' and value '{value}'")

def parse_list(parser):
    l = []

    while True:
        prefix, event, value = next(parser)

        if event == "null":
            l.append(value)
        elif event == "boolean":
            l.append(value)
        elif event == "number":
            if (isinstance(value, decimal.Decimal)):
                l.append(float(value))
            else:
                l.append(value)
        elif event == "string":
            l.append(value)
        elif event == "start_array":
            l.append(parse_list(parser))
        elif event == "start_map":
            l.append(parse_dict(parser))
        elif event == "end_array":
            return l
        else:
            raise ValueError(f"Unknown event '{event}' with prefix '{prefix}' and value '{value}'")

def parse_dict(parser):
    d = {}

    while True:
        prefix, event, value = next(parser)

        if event == "map_key":
            d[value] = parse(parser)
        elif event == "end_map":
            return d
        else:
            raise ValueError(f"Unknown event '{event}' with prefix '{prefix}' and value '{value}'")


condition1 = set([
    "Modifies boot configuration settings",
    "Uses Windows command to clear Windows event logs",
    "Manipulates event log permissions likely to enable clearing of logs",
    "Uses Windows APIs to generate a cryptographic key",
    "Attempts to disable System Restore",
    "Attempts to disable Windows Error Reporting",
    "Found URLs related to Tor in process memory dump (e.g. onion services, Tor2Web, and Ransomware)",
    "Attempts to modify desktop wallpaper",
    "Runs bcdedit commands specific to ransomware",
    "Appends known ransomware file extensions to files that have been encrypted",
    "Performs %d file moves indicative of a ransomware file encryption process",
    "Appends a new file extension or content to %d files indicative of a ransomware file encryption process",
    "unknown file mime types indicative of ransomware writing encrypted files back to disk",
    "Deletes a large number of files from the system indicative of ransomware, wiper malware or system destruction",
    "Creates known ransomware decryption instruction / key file.",
    "Writes a potential ransom message to disk",
    "Displays a potential ransomware message to the user (check screenshots)",
    "Empties the Recycle Bin, indicative of Ransomware",
    "Removes the Shadow Copy to avoid recovery of the system",
    "Uses wbadmin utility to delete backups or configuraton to prevent recovery of the system",
    "Creates known Chanitor Ransomware mutexes",
    "Creates known Crilock/Cryptolocker files, registry keys and/or mutexes",
])

condition2 = set([
    "Expresses interest in specific running processes",
    "Searches running processes potentially to identify processes for sandbox evasion, code injection or memory dumping",
    "Repeatedly searches for a not-found process, you may want to run a web browser during analysis",
    "Queries for the computername",
    "Queries the disk size which could be used to detect virtual machine with small fixed size or dynamic allocation",
    "Queries information on disks, possibly for anti-virtualization",
    "Disables Windows Security features",
    "The binary likely contains encrypted or compressed data indicative of a packer",
    "Installs itself for autorun at Windows startup",
    "Installs a native executable to run on early Windows boot",
    "Queries for potentially installed applications",
    "Executes one or more WMI queries",
    "Executes one or more WMI queries which can be used to identify virtual machines",
    "Executes one or more WMI queries which can be used for persistance",
    "Executes one or more WMI queries which can be used to create or modify services",
])

def extract_brief_process_tree(origin_list):
    l = []
    for info in origin_list:
        d = {
            "进程名": info["process_name"],
            "进程号": info["pid"],
            "命令行": info["command_line"],
            "子进程": extract_brief_process_tree(info["children"] or [])
        }
        l.append(d)
    return l

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: {0} <json-file>".format(sys.argv[0]), file=sys.stderr)

    info = None
    target = None
    signatures = None
    behavior_processtree = None
    behavior_processes = None
    behavior_summary = None

    with open(sys.argv[1], "r", encoding="gb2312") as f:
        parser = ijson.parse(f)

        while True:
            try:
                prefix, event, value = next(parser)
            except StopIteration:
                break

            if (prefix, event) == ("info", "start_map"):
                info = parse_dict(parser)
                with open("info.json", "w", encoding="utf-8") as outfile:
                    json.dump(info, outfile, ensure_ascii=False, indent=2)
            elif (prefix, event) == ("target", "start_map"):
                target = parse_dict(parser)
                with open("target.json", "w", encoding="utf-8") as outfile:
                    json.dump(target, outfile, ensure_ascii=False, indent=2)
            elif (prefix, event) == ("signatures", "start_array"):
                signatures = parse_list(parser)
                with open("signatures.json", "w", encoding="utf-8") as outfile:
                    json.dump(signatures, outfile, ensure_ascii=False, indent=2)
            elif (prefix, event) == ("behavior.processtree", "start_array"):
                behavior_processtree = parse_list(parser)
                with open("behavior.processtree.json", "w", encoding="utf-8") as outfile:
                    json.dump(behavior_processtree, outfile, ensure_ascii=False, indent=2)
            # elif (prefix, event) == ("behavior.processes", "start_array"):
            #     behavior_processes = parse_list(parser)
            #     with open("behavior.processes.json", "w", encoding="utf-8") as outfile:
            #         json.dump(behavior_processes, outfile, ensure_ascii=False, indent=2)
            elif (prefix, event) == ("behavior.summary", "start_map"):
                behavior_summary = parse_dict(parser)
                with open("behavior.summary.json", "w", encoding="utf-8") as outfile:
                    json.dump(behavior_summary, outfile, ensure_ascii=False, indent=2)
            elif (prefix, event) == ("", "end_map"):
                break

    res = {
        "威胁类型": None,
        "恶意评分": None,
    }

    sig_descs = set()
    for signature in signatures:
        sig_descs.add(signature["description"])

    if (sig_descs & condition1) and (sig_descs & condition2):
        res["威胁类型"] = "勒索病毒"
    elif info["score"] >= 10:
        res["威胁类型"] = "恶意软件"

    res["恶意评分"] = info["score"]

    res["文件信息"] = {
        "文件名称": target[target["category"]]["name"],
        "文件类型": target[target["category"]]["type"],
        "文件大小": target[target["category"]]["size"],
        "MD5": target[target["category"]]["md5"],
        "SHA1": target[target["category"]]["sha1"]
    }

    res["行为分析"] = {
        "进程行为": extract_brief_process_tree(behavior_processtree),
        "文件行为": {
            "创建文件": list(set(os.path.basename(path) for path in behavior_summary["file_created"]))
        },
        # @todo
        "网络行为": {
            "IP地址": []
        }
    }

    # @todo ttp is empty
    res["MITRE ATT&CK™ 矩阵（技术）检测"] = list(sig["ttp"] for sig in signatures)

    res["恶意指标"] = {
        "高危险等级": [],
        "中危险等级": [],
        "低危险等级": []
    }

    for signature in signatures:
        if 3 <= signature["severity"] <= 6:
            category = "高危险等级"
        elif signature["severity"] == 2:
            category = "中危险等级"
        elif signature["severity"] == 1:
            category = "低危险等级"
        else:
            continue
        
        item = {
            "描述": signature["description"],
            "恶意指标": [],
            "调用接口": [],
            # @todo "类型": None
        }

        for mark in signature["marks"]:
            if mark["type"] == "ioc":
                item["恶意指标"].append(mark["ioc"])
            elif mark["type"] == "call":
                item["调用接口"].append(mark["call"]["api"])

        res["恶意指标"][category].append(item)
        
    print(json.dumps(res, ensure_ascii=False, indent=2))
