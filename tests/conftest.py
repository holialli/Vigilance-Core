import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def artifact_df():
    """A small artifact frame shaped like carve_evidence_from_image() output."""
    return pd.DataFrame([
        {
            'Date and Time': '2024-03-01 09:15:00', 'Event ID': '4624',
            'Task Category': 'TargetUserName: alice | LogonType: 2',
            'LogSource': 'SECURITY', 'Keywords': 'None', 'ArtifactType': 'EVTX',
        },
        {
            'Date and Time': '2024-03-01 03:02:00', 'Event ID': '1102',
            'Task Category': 'The audit log was cleared',
            'LogSource': 'SECURITY', 'Keywords': 'Alert', 'ArtifactType': 'EVTX',
        },
        {
            'Date and Time': '2024-03-01 11:00:00', 'Event ID': '9100',
            'Task Category': 'SAM User Account: alice (RID: 1001) | Login Count: 42 | Last Logon: 2024-03-01 09:15:00',
            'LogSource': 'SAM', 'Keywords': 'Alert', 'ArtifactType': 'SAM',
        },
        {
            'Date and Time': '2024-03-01 12:00:00', 'Event ID': '7000',
            'Task Category': r'Registry [SYSTEM] ControlSet001\Control\ComputerName\ComputerName\ComputerName = WORKSTATION-7',
            'LogSource': 'REGISTRY', 'Keywords': 'None', 'ArtifactType': 'REGISTRY',
        },
    ])
