"""Run the pinned WMS wallpaper sizing method in Java; no device/build mutation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SOURCE = 'frameworks/base/services/core/java/com/android/server/wm/WallpaperWindowToken.java'
SHA256 = '544d7d3d0a62939b86b09c4b184d4d749813722b9d738271dbab7e1c01d09bd1'


def extract_method(text):
    start = text.index('    void adjustWindowParams(WindowState win, WindowManager.LayoutParams attrs) {')
    opening = text.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


HARNESS = r'''
    static class ViewGroup { static class LayoutParams { static final int MATCH_PARENT=-1; } }
    static class WindowManager {
        static class LayoutParams {
            static final int FLAG_SCALED=0x4000;
            int width,height,flags;
            LayoutParams(int w,int h) { width=w; height=h; }
        }
    }
    static class DisplayInfo {
        int logicalWidth,logicalHeight;
        DisplayInfo(int w,int h) { logicalWidth=w; logicalHeight=h; }
    }
    static class WindowState {
        DisplayInfo info;
        WindowState(int w,int h) { info=new DisplayInfo(w,h); }
        DisplayInfo getDisplayInfo() { return info; }
    }
    static int[] frame(int w,int h,int dw,int dh) {
        WindowManager.LayoutParams attrs=new WindowManager.LayoutParams(w,h);
        new WallpaperGeometryHost().adjustWindowParams(new WindowState(dw,dh),attrs);
        if (attrs.flags!=WindowManager.LayoutParams.FLAG_SCALED) throw new AssertionError();
        return new int[]{attrs.width,attrs.height};
    }
    static boolean same(int[] a,int[] b) { return a[0]==b[0] && a[1]==b[1]; }
    static void check(boolean condition) { if (!condition) throw new AssertionError(); }
    public static void main(String[] args) {
        int[][] displays={{240,320},{320,240}};
        int[][] original=new int[displays.length][];
        int minW=64,minH=64;
        float maxScale=1.10f;
        for (int i=0;i<displays.length;i++) {
            original[i]=frame(1243,1024,displays[i][0],displays[i][1]);
            minW=Math.max(minW,(int)Math.ceil(original[i][0]*maxScale)+1);
            minH=Math.max(minH,(int)Math.ceil(original[i][1]*maxScale)+1);
        }
        int bestW=1243,bestH=1024;
        // Bounded exploratory search, not a product sizing implementation.
        for (int w=minW;w<=Math.min(1243,minW+63);w++) {
            for (int h=minH;h<=Math.min(1024,minH+63);h++) {
                boolean match=true;
                for (int i=0;i<displays.length;i++)
                    match &= same(original[i],frame(w,h,displays[i][0],displays[i][1]));
                if (match && (long)w*h < (long)bestW*bestH) { bestW=w; bestH=h; }
            }
        }
        check(same(original[0],new int[]{388,320}));
        check(same(original[1],new int[]{320,263}));
        check(!same(original[0],frame(428,353,240,320)));
        check(bestW==429 && bestH==353);
        int offsetsChecked=0;
        for (int i=0;i<displays.length;i++) {
            int[] resized=frame(bestW,bestH,displays[i][0],displays[i][1]);
            check(same(original[i],resized));
            check(bestW>=original[i][0]*maxScale && bestH>=original[i][1]*maxScale);
            // Exact WMS offset arithmetic for sampled normalized offsets, both axes.
            for (int axis=0;axis<2;axis++) for (float p:new float[]{0f,.125f,.5f,.875f,1f}) {
                int oldAvail=original[i][axis]-displays[i][axis];
                int newAvail=resized[axis]-displays[i][axis];
                check((oldAvail>0 ? -(int)(oldAvail*p+.5f):0)
                        ==(newAvail>0 ? -(int)(newAvail*p+.5f):0));
                offsetsChecked++;
            }
        }
        WindowManager.LayoutParams unchanged=new WindowManager.LayoutParams(-1,1024);
        new WallpaperGeometryHost().adjustWindowParams(new WindowState(240,320),unchanged);
        check(unchanged.width==-1 && unchanged.height==1024 && unchanged.flags==0);
        System.out.printf("{\"original_buffer\":[1243,1024],\"portrait_frame\":[388,320],"
                +"\"landscape_frame\":[320,263],\"max_scale_model\":1.10,"
                +"\"lower_bound_with_one_pixel_guard\":[%d,%d],\"candidate_buffer\":[%d,%d],"
                +"\"offset_checks\":%d,\"match_parent_control\":true}%n",
                minW,minH,bestW,bestH,offsetsChecked);
    }
'''


def run(source_root, output):
    raw = (source_root / SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError('WMS source changed; review the method and update the source gate')
    method = extract_method(raw.decode())
    output.mkdir(parents=True, exist_ok=True)
    java = output / 'WallpaperGeometryHost.java'
    java.write_text('public class WallpaperGeometryHost {\n' + method + '\n' + HARNESS + '\n}\n')
    compile_result = subprocess.run(['javac', '-Xlint:all', '-Werror', str(java)], capture_output=True, text=True)
    if compile_result.returncode:
        raise RuntimeError(compile_result.stderr)
    result = subprocess.run(['java', '-cp', str(output), 'WallpaperGeometryHost'], capture_output=True, text=True, check=True)
    report = dict(source=SOURCE, source_sha256=SHA256,
                  extracted_method_sha256=hashlib.sha256(method.encode()).hexdigest(),
                  generated_java_sha256=hashlib.sha256(java.read_bytes()).hexdigest(),
                  javac_exit=compile_result.returncode, java_exit=result.returncode,
                  model=json.loads(result.stdout),
                  limits=['Exact extracted WMS method with modeled LayoutParams/DisplayInfo/WindowState only.',
                          'Default 240x320 mode and transpose only; not device rotation acceptance.',
                          '1.10 is a source/runtime-transform model, not a live resolved resource read.',
                          'Integer frame/offset equality does not prove identical filtering, pixels, GL lifecycle or RAM savings.',
                          'No product patch, target compilation, shared source mutation or handset command.'])
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.source_root, args.output), indent=2))
