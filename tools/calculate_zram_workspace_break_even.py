"""Conditional allocator/workspace arithmetic, not an Android compression forecast."""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from statistics import median


def integer(value):
    value = Fraction(str(value))
    if value.denominator != 1: raise ValueError('Require integer byte count')
    return value.numerator


def number(value):
    return dict(numerator=value.numerator, denominator=value.denominator, decimal=float(value))


def calculate(scratch_path, pair_path):
    scratch = json.loads(scratch_path.read_text()); pair = json.loads(pair_path.read_text())
    workspace = Path(scratch['workspace_evidence'])
    if hashlib.sha256(workspace.read_bytes()).hexdigest() != scratch['workspace_evidence_sha256']:
        raise ValueError('Historical workspace evidence differs')
    if pair['candidate']['protocol']['image'] != '47':
        raise ValueError('Require the observed image47 candidate arm')
    phases = scratch['phases']
    if [p['algorithm'] for p in phases] != ['lzo', 'zstd', 'zstd', 'lzo']:
        raise ValueError('Unexpected scratch experiment order')
    if any(not p['probe']['readback_verified'] or p['probe']['bytes'] != 4194304 or not p['cpus_stable'] for p in phases):
        raise ValueError('Incomplete/different scratch corpus')
    if len({p['probe']['checksum'] for p in phases}) != 1:
        raise ValueError('Scratch corpus differs')
    if any(p['initialized']['online_cpus'] != [0, 1, 2, 3] for p in phases):
        raise ValueError('Expected historical four-CPU workspace scenario')
    alloc = {name: integer(median([p['filled']['zram']['zsmalloc_physical_bytes'] for p in phases if p['algorithm'] == name])) for name in ['lzo', 'zstd']}
    work = {}
    for name in ['lzo', 'zstd']:
        key = 'conditional_workspace_request_bytes' if name == 'lzo' else 'init_zstd_reported_backing_delta_bytes'
        values = {integer(p[key]) for p in phases if p['algorithm'] == name}
        if len(values) != 1: raise ValueError('Workspace scenario changed')
        work[name] = values.pop()
    if alloc['lzo'] <= 0 or alloc['zstd'] >= alloc['lzo'] or work['zstd'] <= work['lzo']:
        raise ValueError('This calculation requires lower zstd allocator usage and higher fixed workspace')
    saving_ratio = 1 - Fraction(alloc['zstd'], alloc['lzo'])
    extra = work['zstd'] - work['lzo']
    threshold = Fraction(extra) / saving_ratio
    scratch_delta = alloc['zstd'] + work['zstd'] - alloc['lzo'] - work['lzo']
    if scratch_delta != integer(scratch['comparison']['conditional_zsmalloc_plus_workspace_bytes']['zstd_minus_lzo']):
        raise ValueError('Scratch published total does not reconcile')
    if not pair['eligible_for_descriptive_timed_idle_comparison'] or pair['comparison_failures']:
        raise ValueError('Pair is not a qualified source for its observed allocator sizes')
    rows = []
    for snapshot in pair['global_snapshots']:
        capacity = integer(Fraction(str(snapshot['candidate']['zram_physical_KiB'])) * 1024)
        rows.append(dict(phase=snapshot['phase'], observed_image47_allocator_bytes=capacity,
            required_allocator_improvement_to_offset_workspace=number(Fraction(extra, capacity)),
            conditional_zstd_minus_lzo_bytes=number(Fraction(extra) - capacity * saving_ratio)))
    return dict(status='Conditional four-stream arithmetic only; no compressor trial or prediction',
        source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [scratch_path, pair_path, workspace]},
        calculator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        historical_scratch=dict(corpus_bytes=4194304, samples_per_algorithm=2, zsmalloc_bytes=alloc,
            workspace_bytes=work, lzo_workspace_basis='Modeled request, not an independently isolated live physical allocation',
            zstd_workspace_basis='Reported vmalloc backing pages in the historical four-online-CPU trial',
            scratch_zstd_minus_lzo_bytes=scratch_delta),
        formula='delta = extra_workspace - baseline_lzo_zsmalloc_bytes * allocator_improvement_fraction',
        observed_scratch_allocator_improvement=number(saving_ratio), extra_workspace_bytes=extra,
        break_even_lzo_allocator_bytes=number(threshold), break_even_lzo_allocator_MiB=float(threshold / 1048576),
        current_sized_scenarios=rows,
        sensitivity=[dict(assumed_allocator_improvement_percent=percent,
            break_even_lzo_allocator_MiB=float(Fraction(extra * 100, percent) / 1048576) if percent else None)
            for percent in [0, 5, 10, 15, 20, 25, 30]],
        limits=['The scratch allocator ratio is not established for real Android pages, workloads or larger fills; packing is not necessarily linear.',
                'Image47 values supply allocator size only. Its current algorithm/online stream allocation is not freshly queried here; scenarios assume these sizes were a LZO baseline.',
                'Four-stream workspace is historical; do not assume a supported one-stream tuning knob or offline CPUs.',
                'Other metadata, vmalloc page tables, fragmentation, CPU/battery/latency and workload changes are excluded.',
                'At zero fill the extra fixed workspace costs memory before compression can offset it; a later positive scenario does not prove safe boot or lower peak RAM.',
                'Workspace and zsmalloc already lie inside occupied RAM. Never add the modeled change again to global snapshots.',
                'No active swap reset, swapoff, CPU change, host build or phone command. Any future trial requires a separate fresh boot and matching framework baseline.'],
        savings_proven=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['scratch', 'pair', 'output']: p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args(); report = calculate(a.scratch, a.pair)
    with a.output.open('x') as file: file.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ['extra_workspace_bytes', 'break_even_lzo_allocator_MiB', 'current_sized_scenarios']}, indent=2))
