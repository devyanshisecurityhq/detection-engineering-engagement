#!/usr/bin/env python3
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser
import os

EVTX_DIR = "datasets/EVTX-ATTACK-SAMPLES/Execution"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


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
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for data in event_data.findall("e:Data", NS):
            name = data.attrib.get("Name")
            if name:
                event[name] = data.text
    return event


for f in os.listdir(EVTX_DIR):
    if not f.endswith(".evtx"):
        continue
    path = os.path.join(EVTX_DIR, f)
    try:
        parser = PyEvtxParser(path)
        for record in parser.records():
            event = parse_event(record["data"])
            if event is None:
                continue
            image = (event.get("Image") or "").lower()
            if "powershell" in image or "pwsh" in image:
                print(f"FILE: {f}")
                print(f"  EventID:     {event.get('EventID')}")
                print(f"  Image:       {event.get('Image')}")
                print(f"  CommandLine: {event.get('CommandLine')}")
                print(f"  ParentImage: {event.get('ParentImage')}")
                print()
    except Exception as e:
        pass
