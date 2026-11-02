"""Classify a bounded startup capture without treating missing samples as success."""


def summarize(samples, expected_image, observer_error=None, final_logcat_exit=None):
    connected = []
    gaps = []
    identities = set()
    failures = []
    if observer_error:
        failures.append('observer_error')
    if final_logcat_exit is not None:
        failures.append('log_stream_interrupted')
    first = None
    for index, row in enumerate(samples):
        output = row.get('output', [])
        valid = row.get('returncode') == 0 and len(output) >= 4
        if valid:
            if first is None:
                first = index
            connected.append(index)
            identities.add((output[0], output[1]))
            if output[0] != str(expected_image) or not output[1]:
                failures.append('identity_mismatch')
        elif first is not None:
            gaps.append(index)
        if row.get('previous_logcat_exit') is not None or row.get('logcat_exit') is not None:
            failures.append('log_stream_interrupted')
    if not connected:
        failures.append('no_connected_samples')
    if len(identities) > 1:
        failures.append('identity_changed')
    if gaps:
        failures.append('transport_gap_after_first_connection')
    final_connected = bool(samples and connected and connected[-1] == len(samples)-1)
    final_boot_complete = final_connected and samples[-1]['output'][2] == '1'
    if not final_connected:
        failures.append('final_sample_unavailable')
    elif not final_boot_complete:
        failures.append('final_boot_not_complete')
    if any(not samples[index].get('logcat_segment') for index in connected):
        failures.append('log_stream_not_started')
    return dict(classification='incomplete' if failures else 'bounded_connected_observation',
                expected_image=str(expected_image), samples=len(samples),
                connected_samples=len(connected), initial_wait_samples=first,
                gap_sample_indices=gaps, final_connected=final_connected,
                final_boot_complete=final_boot_complete, failures=sorted(set(failures)),
                physical_acceptance=False, full_boot_log_completeness_proven=False)
