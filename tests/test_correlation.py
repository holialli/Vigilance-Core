import pandas as pd

from forensics.correlation import (build_correlations, extract_entities,
                                   find_temporal_cluster, init_correlation_db,
                                   pivot_entity, top_entities)


def test_extracts_username_from_event_log():
    found = extract_entities("TargetUserName: BillyBob | TargetDomainName: HOST")
    assert ("user", "BillyBob") in found


def test_extracts_username_from_sam():
    found = extract_entities("SAM User Account: Jimmy Wilson (RID: 1004)")
    assert ("user", "Jimmy Wilson") in found


def test_extracts_usb_serial():
    found = extract_entities("USB Device: LEXAR (Vendor: x, Serial: I145291811100&0)")
    assert ("usb_serial", "I145291811100") in found


def test_usb_serial_forms_normalize_to_one_entity():
    """USBSTOR's instance suffix must not split a device into two entities."""
    usbstor = extract_entities("USB Device: LEXAR (Vendor: x, Serial: I145291811100&0)")
    attached = extract_entities(
        r"USB Device Attached: USB Mass Storage Device "
        r"(ID: VID_05DC&PID_0080\I145291811100)"
    )
    assert usbstor == attached == {("usb_serial", "I145291811100")}


def test_usb_hubs_are_not_treated_as_serials():
    found = extract_entities(r"USB Device Attached: USB Root Hub (ID: ROOT_HUB\4&1e573aba&0)")
    assert not any(t == "usb_serial" for t, _ in found)


def test_extracts_executable():
    found = extract_entities(r"Program Execution Evidence: C:\tools\nc.exe")
    assert ("executable", "nc.exe") in found


def test_machine_accounts_and_noise_filtered():
    found = extract_entities("TargetUserName: HOST$ | TargetUserName: SYSTEM")
    assert not any(t == "user" for t, _ in found)


def test_correlates_entity_across_artifact_types():
    df = pd.DataFrame([
        {'Date and Time': '2024-03-01 09:00:00', 'ArtifactType': 'EVTX',
         'LogSource': 'SECURITY', 'Task Category': 'TargetUserName: BillyBob'},
        {'Date and Time': '2024-03-01 10:00:00', 'ArtifactType': 'SAM',
         'LogSource': 'SAM', 'Task Category': 'SAM User Account: BillyBob (RID: 1001)'},
    ])
    conn = build_correlations(df)
    leads = top_entities(conn, min_types=2)
    assert "billybob" in leads['Entity'].tolist()


def test_single_source_entity_excluded_from_leads():
    df = pd.DataFrame([{
        'Date and Time': '2024-03-01 09:00:00', 'ArtifactType': 'EVTX',
        'LogSource': 'SECURITY', 'Task Category': 'TargetUserName: OnlyOnce',
    }])
    leads = top_entities(build_correlations(df), min_types=2)
    assert "onlyonce" not in leads['Entity'].tolist()


def test_named_entity_type_shows_single_source_entities():
    """A USB serial only ever appears in USB rows; requiring two sources hid them."""
    df = pd.DataFrame([{
        'Date and Time': '2024-03-01 09:00:00', 'ArtifactType': 'USB',
        'LogSource': 'REGISTRY',
        'Task Category': 'USB Device: LEXAR (Vendor: x, Serial: I145291811100&0)',
    }])
    conn = build_correlations(df)
    assert top_entities(conn).empty                      # "All" still needs 2 sources
    assert "i145291811100" in top_entities(
        conn, entity_type="usb_serial")['Entity'].tolist()


def test_all_rows_indexed_regardless_of_position():
    """Artifacts concat one type at a time, so a head() cap drops whole types."""
    rows = [{'Date and Time': '2024-03-01 09:00:00', 'ArtifactType': 'EVTX',
             'LogSource': 'SECURITY', 'Task Category': 'TargetUserName: Filler'}
            for _ in range(200)]
    rows.append({'Date and Time': '2024-03-01 10:00:00', 'ArtifactType': 'USB',
                 'LogSource': 'REGISTRY',
                 'Task Category': 'USB Device: X (Vendor: y, Serial: LASTONE123&0)'})
    conn = build_correlations(pd.DataFrame(rows))
    assert "lastone123" in top_entities(
        conn, entity_type="usb_serial")['Entity'].tolist()


def test_pivot_collapses_identical_descriptions():
    df = pd.DataFrame([
        {'Date and Time': f'2024-03-0{i} 09:00:00', 'ArtifactType': 'REGISTRY',
         'LogSource': 'REGISTRY', 'Task Category': 'TargetUserName: BillyBob'}
        for i in range(1, 6)
    ])
    hits = pivot_entity(build_correlations(df), "BillyBob")
    assert len(hits) == 1
    assert hits.iloc[0]['Occurrences'] == 5
    assert hits.iloc[0]['First Seen'] == '2024-03-01 09:00:00'
    assert hits.iloc[0]['Last Seen'] == '2024-03-05 09:00:00'


def test_pivot_returns_all_mentions():
    df = pd.DataFrame([
        {'Date and Time': '2024-03-01 09:00:00', 'ArtifactType': 'EVTX',
         'LogSource': 'SECURITY', 'Task Category': 'TargetUserName: BillyBob'},
        {'Date and Time': '2024-03-01 10:00:00', 'ArtifactType': 'SAM',
         'LogSource': 'SAM', 'Task Category': 'SAM User Account: BillyBob (RID: 1)'},
    ])
    hits = pivot_entity(build_correlations(df), "BillyBob")
    assert len(hits) == 2


def test_empty_dataframe_is_safe():
    conn = build_correlations(pd.DataFrame(), init_correlation_db())
    assert top_entities(conn).empty


def test_temporal_cluster_finds_nearby_events():
    df = pd.DataFrame([
        {'Date and Time': '2024-03-01 09:00:00', 'ArtifactType': 'EVTX',
         'LogSource': 'S', 'Event ID': '1', 'Task Category': 'anchor'},
        {'Date and Time': '2024-03-01 09:05:00', 'ArtifactType': 'USB',
         'LogSource': 'U', 'Event ID': '2', 'Task Category': 'nearby'},
        {'Date and Time': '2024-03-05 09:00:00', 'ArtifactType': 'EVTX',
         'LogSource': 'S', 'Event ID': '3', 'Task Category': 'far away'},
    ])
    cluster = find_temporal_cluster(df, '2024-03-01 09:00:00', window_minutes=10)
    assert len(cluster) == 2
    assert 'far away' not in cluster['Task Category'].tolist()


def test_temporal_cluster_invalid_anchor():
    df = pd.DataFrame([{'Date and Time': '2024-03-01 09:00:00',
                        'ArtifactType': 'EVTX', 'LogSource': 'S',
                        'Event ID': '1', 'Task Category': 'x'}])
    assert find_temporal_cluster(df, "not-a-date").empty
