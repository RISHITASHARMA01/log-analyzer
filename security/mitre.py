TECHNIQUES = {
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion / Initial Access"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1222.001": ("Windows Permissions Modification", "Defense Evasion"),
    "T1222.002": ("Linux Permissions Modification", "Defense Evasion"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
}

def get_technique(technique_id):
    name, tactic = TECHNIQUES[technique_id]
    return {
        "technique_id": technique_id,
        "technique_name": name,
        "tactic": tactic,
        "reference": "https://attack.mitre.org/techniques/"
                     + technique_id.replace(".", "/") + "/"
    }
