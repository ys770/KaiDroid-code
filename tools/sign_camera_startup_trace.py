"""Sign the audited timing-only camera candidate using the shared signer checks.

Use the sign_reviewed_tcl_app CLI arguments with --app camera-startup-trace.
This wrapper adds one exact candidate without changing other lanes' registry.
"""
from sign_reviewed_tcl_app import APPS, main

APPS['camera-startup-trace'] = dict(
    sha256='b8906b64c9e016e6866a658ef7b21d936615a4537bb9e49fb9ddc53c0d3e2edc',
    package='com.tcl.camera', version='511004100', key='platform',
    certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8')

if __name__ == '__main__':
    main()
