"""Future read-only Home observation; transient null never triggers another key."""
import re,time

def focus(text):
 rows=[s.strip() for s in text.splitlines() if s.strip().startswith('mCurrentFocus=')]
 if rows==['mCurrentFocus=null']:return None
 if len(rows)!=1:raise ValueError('Missing/ambiguous current-focus record')
 match=re.fullmatch(r'mCurrentFocus=Window\{([0-9a-f]+) u0 ([^}]+)\}',rows[0])
 if not match:raise ValueError('Malformed current-focus record')
 return list(match.groups())

def observe(read_window,expected,seconds=12,interval=.5,now=None,pause=None,on_sample=None):
 """Caller sends Home once beforehand. This function can only read/wait/record.

 A different token on the same component remains a strict mismatch. This
 reports observations and never assigns a user-facing navigation verdict.
 """
 if len(expected)!=2 or not all(isinstance(s,str) and s for s in expected):raise ValueError('Expected exact window/component pair required')
 if not 0<seconds<=30 or not 0<interval<=1:raise ValueError('Bounded observation limits required')
 now=time.monotonic if now is None else now;pause=time.sleep if pause is None else pause
 deadline=now()+seconds;observations=[];different=False
 while True:
  current=focus(read_window());observations.append(current)
  component=bool(current and current[1]==expected[1])
  different=different or bool(component and current[0]!=expected[0])
  sample=dict(current_window=current,exact_original_window=current==expected,home_component_observed=component,
   same_component_different_window_observed=different,samples=len(observations))
  if on_sample:on_sample(dict(sample))
  if sample['exact_original_window'] or now()>=deadline:
   return dict(**sample,observations=observations,home_input_requested=False,complete_ui_parity=False)
  pause(min(interval,max(0,deadline-now())))
