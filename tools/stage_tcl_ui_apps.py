"""Add pinned standalone modules to an idle, coordinated build tree without replacing files."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'destination', 'stage'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--stock-apps', action='store_true')
    parser.add_argument('--media-apps', action='store_true')
    args = parser.parse_args()
    if args.stock_apps and args.media_apps:
        raise ValueError('Select one app set')
    if args.destination.exists() or args.stage.exists():
        raise FileExistsError('Destination and stage must both be new')
    names = (('TclMusic', 'TctSoundRecorder', 'TctCamera') if args.media_apps else
             ('FPCalendar', 'FPDeskClock', 'JrdGallery', 'Calculator', 'Note', 'FileManager')
             if args.stock_apps else ('FPContacts', 'FPMessaging', 'GcsDialer', 'TctSettings'))
    expected = {'provenance.json'} | {n + '/' + f for n in names for f in (n + '.apk', 'Android.mk')}
    with tarfile.open(args.archive) as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != expected:
            raise ValueError('Unexpected archive entries')
        if not all(m.isfile() for m in members):
            raise ValueError('Only regular files are accepted')
        data = {m.name: archive.extractfile(m).read() for m in members}
    provenance = json.loads(data['provenance.json'])
    if len(provenance['apps']) != len(names) or {a['name'] for a in provenance['apps']} != set(names):
        raise ValueError('Unexpected apps')
    for app in provenance['apps']:
        if args.stock_apps or args.media_apps:
            privileged = not args.stock_apps
            if app.get('privileged_module') is not privileged:
                raise ValueError('App privilege placement changed')
            module = data[app['name'] + '/Android.mk'].decode()
            if 'LOCAL_PRIVILEGED_MODULE := ' + str(privileged).lower() + '\n' not in module:
                raise ValueError('App module privilege placement disagrees with provenance')
        path = app['name'] + '/' + app['name'] + '.apk'
        if hashlib.sha256(data[path]).hexdigest() != app['sha256']:
            raise ValueError('Payload hash mismatch: ' + path)
    args.stage.mkdir(parents=True, exist_ok=False)
    args.destination.mkdir(parents=True, exist_ok=False)
    for name, payload in data.items():
        path = args.destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(payload)
    report = dict(destination=str(args.destination), stock_apps=args.stock_apps, media_apps=args.media_apps,
                  files={n: hashlib.sha256(d).hexdigest() for n, d in data.items()},
                  product_selected=False, built=False, installed=False)
    (args.stage / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
