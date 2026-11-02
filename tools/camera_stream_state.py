"""Read the active Camera3 stream configuration, excluding static capabilities."""
import re


def active_streams(text):
    if text.count('    Stream configuration:') != 1:
        raise ValueError('Expected exactly one active camera stream configuration')
    block = text.split('    Stream configuration:', 1)[1].split('    Camera3 Buffer Manager:', 1)[0]
    rows = []
    for part in re.split(r'    Stream\[\d+\]: Output', block)[1:]:
        consumer = re.search(r'Consumer name: (.+)', part)
        dimensions = re.search(r'Dims: (\d+) x (\d+), format (0x[0-9a-f]+)', part)
        frames = re.search(r'Frames produced: (\d+)', part)
        if not all((consumer, dimensions, frames)):
            raise ValueError('Incomplete active stream description')
        rows.append(dict(consumer=consumer[1].strip(), width=int(dimensions[1]),
                         height=int(dimensions[2]), format=dimensions[3], frames=int(frames[1])))
    return rows


def require_mode(text, mode, recording=False):
    rows = active_streams(text)
    previews = [r for r in rows if r['consumer'].startswith('SurfaceView - com.tcl.camera/')]
    if len(previews) != 1 or previews[0]['frames'] <= 0:
        raise ValueError('TCL preview has not produced frames')
    jpeg = [r for r in rows if r['format'] == '0x21' and r['consumer'].startswith('ImageReader-')]
    video = [r for r in rows if r['consumer'] == 'GraphicBufferSource']
    if mode == 'photo':
        if len(jpeg) != 1 or video:
            raise ValueError('Expected photo streams before mode change')
    elif mode == 'video':
        if len(video) != 1 or jpeg or (recording and video[0]['frames'] <= 0):
            raise ValueError('Expected video encoder stream and requested frame evidence')
    else:
        raise ValueError('Unknown expected mode')
    return rows


def active_mode(text):
    """Recognize either supported module; reject ambiguous or incomplete streams."""
    for mode in ('photo', 'video'):
        try:
            require_mode(text, mode)
        except ValueError:
            continue
        return mode
    raise ValueError('No unambiguous active photo/video module')
