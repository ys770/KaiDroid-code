"""Stage a donor-ordered, bounded picker-to-editor handover; never installs."""
import argparse
import hashlib
import json
from pathlib import Path

PINS={'KeypadImeController.java':'99ba4437bbee6f42cd363069ec85c6a9448431fdc2ba5ff61c9e8cee855d37cc',
      'KeypadImeModeState.java':'cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806'}

def once(text,old,new):
 if text.count(old)!=1:raise ValueError('Unexpected installed-source anchor: '+old[:70])
 return text.replace(old,new)

def sources(inputs):
 files={}
 for name,pin in PINS.items():
  data=(inputs/name).read_bytes()
  if hashlib.sha256(data).hexdigest()!=pin:raise ValueError('Wrong native12 source: '+name)
  files[name]=data.decode()
 state=files['KeypadImeModeState.java']
 state=once(state,'    private long generation;','    private long generation;\n    private long ownershipGeneration;')
 state=once(state,'    private void invalidate() {\n        generation++;','    private void invalidate() {\n        ownershipGeneration++;\n        generation++;')
 state=once(state,'    public long generation() { return generation; }','    public long generation() { return generation; }\n\n    long ownershipGeneration() { return ownershipGeneration; }')
 text=files['KeypadImeController.java']
 text=once(text,'    private long pickerFocusDeadline;','    private long pickerFocusDeadline;\n    private Runnable pendingSelection;')
 text=once(text,'        handler.removeCallbacks(refresh);\n        dismissPicker();','        handler.removeCallbacks(refresh);\n        cancelSelection();\n        dismissPicker();')
 text=once(text,'        editor = next;','        if (editor != next) cancelSelection();\n        editor = next;')
 start=text.index('                    for (String action : actions) {')
 end=text.index('\n                });',start)
 text=text[:start]+'''                    queueSelection(owner, state.ownershipGeneration(), choice,
                            new ArrayList<>(actions));'''+text[end:]
 method='''    private void cancelSelection() {
        if (pendingSelection != null) handler.removeCallbacks(pendingSelection);
        pendingSelection = null;
    }

    private void queueSelection(View owner, long ownership, String choice, List<String> actions) {
        cancelSelection();
        final long deadline = SystemClock.uptimeMillis() + PICKER_FOCUS_TIMEOUT_MS;
        pendingSelection = new Runnable() {
            @Override public void run() {
                if (pendingSelection != this) return;
                refreshOwner();
                if (pendingSelection != this) return;
                if (editor != owner || state.ownershipGeneration() != ownership
                        || SystemClock.uptimeMillis() >= deadline) {
                    cancelSelection();
                    return;
                }
                // choose() dismisses after its validated callback returns. Wait
                // for the original app window to own focus and its served IME.
                if (picker != null || !bar.hasWindowFocus() || imm == null
                        || !imm.isActive(owner) || status() < 1 || status() > 3) {
                    handler.postDelayed(this, 25);
                    return;
                }
                if (!actions.equals(state.selectionActions(choice))) {
                    cancelSelection();
                    return;
                }
                pendingSelection = null; // Consume once before any side effect.
                for (String action : actions) {
                    refreshOwner();
                    if (editor != owner || state.ownershipGeneration() != ownership
                            || !bar.hasWindowFocus() || !imm.isActive(owner)
                            || !actions.equals(state.selectionActions(choice))) return;
                    context.sendBroadcast(new Intent(action).setPackage(PACKAGE));
                }
                if ("Symbols".equals(choice)) {
                    refreshOwner();
                    int visible = status();
                    if (editor == owner && state.ownershipGeneration() == ownership
                            && bar.hasWindowFocus() && imm.isActive(owner)
                            && actions.equals(state.selectionActions(choice))
                            && visible >= 1 && visible < 3) {
                        imm.showSoftInput(owner, InputMethodManager.SHOW_IMPLICIT);
                    }
                }
            }
        };
        handler.post(pendingSelection);
    }

'''
 text=once(text,'    private void showPicker() {',method+'    private void showPicker() {')
 text=once(text,'        if (picker != null || editor == null || state.label() == null) return;',
           '        if (picker != null || editor == null || state.label() == null) return;\n        cancelSelection();')
 return {'KeypadImeController.java':text.encode(),'KeypadImeModeState.java':state.encode()}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 files=sources(a.inputs);a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():(a.output/name).write_bytes(data)
 report=dict(original_sources=PINS,candidate_sources={n:hashlib.sha256(b).hexdigest() for n,b in files.items()},
  selection_validated_before_dismiss=True,dispatch_queued_after_dismiss=True,ownership_epoch_excludes_focus_only_generation=True,
  deadline_ms=2000,shared_source_modified=False,compiled=False,installed=False,physical_or_full_parity=False)
 (a.output/'source.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
