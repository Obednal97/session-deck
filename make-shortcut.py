#!/usr/bin/env python3
"""Builds the "Ask Deck" iPhone shortcut that Settings > Siri installs. It holds no address or key: on import, Shortcuts
asks for the personal address that Settings copies. iPhones only import signed shortcuts, and signing needs a Mac
signed into iCloud, so run this there (or copy the file over) and sign it:

  python3 make-shortcut.py ask.unsigned.shortcut
  shortcuts sign --mode anyone --input ask.unsigned.shortcut --output ask.shortcut

Then put ask.shortcut next to server.py, or in the deck's data folder (~/Library/Application Support/session-deck) to keep it
out of git; the deck serves it at /api/siri/shortcut."""
import plistlib, sys, uuid

ask, get = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
def var(u, name):  # a text field holding one earlier action's output
    return {"Value": {"string": "￼", "attachmentsByRange": {"{0, 1}": {"OutputName": name, "OutputUUID": u, "Type": "ActionOutput"}}},
            "WFSerializationType": "WFTextTokenString"}
text = lambda s: {"Value": {"string": s}, "WFSerializationType": "WFTextTokenString"}
actions = [
    {"WFWorkflowActionIdentifier": "is.workflow.actions.ask",
     "WFWorkflowActionParameters": {"UUID": ask, "WFAskActionPrompt": "What do you want?", "WFInputType": "Text"}},
    {"WFWorkflowActionIdentifier": "is.workflow.actions.downloadurl",
     "WFWorkflowActionParameters": {"UUID": get, "WFURL": "", "WFHTTPMethod": "POST", "WFHTTPBodyType": "JSON", "ShowHeaders": False,
                                    "WFJSONValues": {"Value": {"WFDictionaryFieldValueItems": [
                                        {"WFItemType": 0, "WFKey": text("text"), "WFValue": var(ask, "Provided Input")}]},
                                        "WFSerializationType": "WFDictionaryFieldValue"}}},
    {"WFWorkflowActionIdentifier": "is.workflow.actions.showresult",
     "WFWorkflowActionParameters": {"Text": var(get, "Contents of URL")}},
]
plistlib.dump({
    "WFWorkflowActions": actions,
    "WFWorkflowImportQuestions": [{"ActionIndex": 1, "Category": "Parameter", "ParameterKey": "WFURL", "DefaultValue": "",
                                   "Text": "Paste the address Session Deck copied for you (Settings, Siri)."}],
    "WFWorkflowClientVersion": "2607.0.2", "WFWorkflowMinimumClientVersion": 900, "WFWorkflowMinimumClientVersionString": "900",
    "WFWorkflowIcon": {"WFWorkflowIconGlyphNumber": 59446, "WFWorkflowIconStartColor": 431817727},
    "WFWorkflowInputContentItemClasses": [], "WFWorkflowOutputContentItemClasses": [], "WFWorkflowTypes": [],
    "WFWorkflowHasShortcutInputVariables": False, "WFQuickActionSurfaces": [],
}, open(sys.argv[1] if len(sys.argv) > 1 else "ask.unsigned.shortcut", "wb"), fmt=plistlib.FMT_BINARY)
