#!/usr/bin/env python3
"""
Threat Hunt 01 — LSASS Memory Access Analysis
Analyzes Sysmon Event ID 10 (Process Access) targeting lsass.exe
"""
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser
from collections import Counter


EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event(xml_string):
    """Parse XML event and return key fields."""
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return None

    event = {}

    # System fields
    system = root.find("e:System", NS)
    if system is not None:
        event_id = system.find("e:EventID", NS)
        event["EventID"] = event_id.text if event_id is not None else None

        time_created = system.find("e:TimeCreated", NS)
        if time_created is not None:
            event["TimeCreated"] = time_created.attrib.get("SystemTime")

        computer = system.find("e:Computer", NS)
        event["Computer"] = computer.text if computer is not None else None

    # EventData fields
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for data in event_data.findall("e:Data", NS):
            name = data.attrib.get("Name")
            value = data.text
            if name:
                event[name] = value

    return event


def main():
    parser = PyEvtxParser(EVTX_FILE)

    total = 0
    lsass_access = []
    source_images = Counter()
    granted_access = Counter()

    for record in parser.records():
        total += 1
        event = parse_event(record["data"])
        if event is None:
            continue

        target = event.get("TargetImage", "")
        if "lsass.exe" in target.lower():
            lsass_access.append(event)
            source_images[event.get("SourceImage", "unknown")] += 1
            granted_access[event.get("GrantedAccess", "unknown")] += 1

    print(f"Total events parsed: {total}")
    print(f"LSASS access events: {len(lsass_access)}")
    print()
    print("=== Source Images (who accessed LSASS) ===")
    for img, count in source_images.most_common(10):
        print(f"  {count:4d}  {img}")
    print()
    print("=== Granted Access Masks ===")
    for mask, count in granted_access.most_common(10):
        print(f"  {count:4d}  {mask}")
    print()
    print("=== First 3 LSASS Access Events ===")
    for event in lsass_access[:3]:
        print(f"  Time:         {event.get('UtcTime')}")
        print(f"  SourceImage:  {event.get('SourceImage')}")
        print(f"  TargetImage:  {event.get('TargetImage')}")
        print(f"  GrantedAccess: {event.get('GrantedAccess')}")
        print(f"  CallTrace:    {event.get('CallTrace', '')[:100]}")
        print()


if __name__ == "__main__":
    main()
