#!/usr/bin/env python3
"""
Threat Hunt 02 — PowerShell Download Cradle Analysis
Analyzes Sysmon Event ID 1 (Process Creation) for suspicious PowerShell
"""
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser
from collections import Counter
import os


EVTX_DIR = "datasets/EVTX-ATTACK-SAMPLES/Execution"

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Download cradle keywords
CRADLE_KEYWORDS = [
    "downloadstring", "downloadfile", "downloaddata",
    "invoke-webrequest", "iwr ", "curl ", "wget ",
    "net.webclient", "start-bitstransfer", "invoke-restmethod",
    "frombase64string", "iex", "invoke-expression",
]


def parse_event(xml_string):
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return None

    event = {}
    system = root.find("e:System", NS)
    if system is not None:
        eid = system.find("e:EventID", NS)
        event["EventID"] = eid.text if eid is not None else None
        tc = system.find("e:TimeCreated", NS)
        if tc is not None:
            event["TimeCreated"] = tc.attrib.get("SystemTime")
        comp = system.find("e:Computer", NS)
        event["Computer"] = comp.text if comp is not None else None

    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for data in event_data.findall("e:Data", NS):
            name = data.attrib.get("Name")
            if name:
                event[name] = data.text

    return event


def main():
    # Find all EVTX files in Execution folder
    evtx_files = []
    for f in os.listdir(EVTX_DIR):
        if f.endswith(".evtx"):
            evtx_files.append(os.path.join(EVTX_DIR, f))

    print(f"Scanning {len(evtx_files)} EVTX files...\n")

    total_events = 0
    powershell_events = []
    cradle_matches = []
    urls_found = set()
    source_files = Counter()

    for evtx_file in evtx_files:
        try:
            parser = PyEvtxParser(evtx_file)
            for record in parser.records():
                total_events += 1
                event = parse_event(record["data"])
                if event is None:
                    continue

                image = (event.get("Image") or "").lower()
                cmdline = (event.get("CommandLine") or "").lower()

                if "powershell" in image or "pwsh" in image:
                    powershell_events.append(event)

                    for kw in CRADLE_KEYWORDS:
                        if kw in cmdline:
                            cradle_matches.append(event)
                            source_files[os.path.basename(evtx_file)] += 1
                            break

                    # Extract URLs
                    for token in cmdline.split():
                        if token.startswith("http://") or token.startswith("https://"):
                            urls_found.add(token[:100])

        except Exception as e:
            print(f"Error parsing {evtx_file}: {e}")

    print(f"Total events parsed:      {total_events}")
    print(f"PowerShell events:        {len(powershell_events)}")
    print(f"Download cradle matches:  {len(cradle_matches)}")
    print()
    print("=== Suspicious Files ===")
    for f, count in source_files.most_common(10):
        print(f"  {count:4d}  {f}")
    print()
    print("=== URLs Found ===")
    for url in list(urls_found)[:10]:
        print(f"  {url}")
    print()
    print("=== First 3 Cradle Matches ===")
    for event in cradle_matches[:3]:
        print(f"  Time:        {event.get('UtcTime')}")
        print(f"  Image:       {event.get('Image')}")
        print(f"  CommandLine: {(event.get('CommandLine') or '')[:150]}")
        print(f"  ParentImage: {event.get('ParentImage')}")
        print(f"  User:        {event.get('User')}")
        print()


if __name__ == "__main__":
    main()
