# Automation - drive a running instance from scripts

Use the automation endpoint for every run that needs input to the guest, a look at the guest screen, or a hardware event, for example a tap, a key, a card insert or a reset. A trace file stays the tool for hooks on guest code.

## How to run a session

1. Start the instance through the runner as a background task. Give its endpoint a name that no other session uses:

   ```
   python claude_cerf_runner.py --timeout=1800 --log-file=tmp/<name>.log --device=<device> --automation=<name>
   ```

2. Write each step as a scratch script under `tmp/`. Connect with the endpoint name from step 1. Each script connects again, and the instance keeps running when a script ends:

   ```python
   import sys
   sys.path.insert(0, r"<repo>\build\Release\<platform>\tools")
   from cerf_automation import Cerf

   cerf = Cerf.connect(endpoint="<name>", wait=60)
   cerf.tap(320, 120)
   cerf.frame().save_png(r"<repo>\tmp\<name>.png")
   cerf.close()
   ```

3. Before the timeout, end the session with a shutdown action through the endpoint.

To run one method from the shell, run `python -m cerf_automation --endpoint <name> call <method> key=value ...` in the `tools` folder. `python -m cerf_automation --endpoint <name> describe` lists the methods, their parameters and the event topics of the instance. Read the list there, not from memory.

## Rules

- Never start a run with a bare `--automation`.
- Never connect by device. Never connect to an instance that `running` lists. Other sessions run the same devices at the same time, so such a connection can reach the instance of another session.
- Find each target in `Cerf.frame()` before you tap it.
- Decide from the screen or from an event, never from a fixed sleep.
- Subscribe before the action whose event you wait for. An event that fires before the subscription is lost.
- A press or a key ends when its connection closes.
- The `save_state_*` actions write the default state image of the device. That image can belong to the user. For a test save, use `state.save` with a path of its own.
- Do not run `save_state_suspend_host`, `save_state_poweroff_host` or `save_state_restart_host`. They act on the host computer.
- Do not capture the host screen. It shows the private windows of the user.

## Changing the endpoint

- A method calls a lever that libCerfCore or the frontend already gives a person. If a script needs a behavior that no lever gives, add the behavior to libCerfCore first.
- The endpoint keeps no machine state.
- An answer that `socket.insert` carries reaches the command inside `MachineRequests::Ask`, on the thread of the insert. `MachineRequests` therefore calls its listeners outside its lock. Every other answerer skips a request that is no longer pending.
- The code is in `cerf-qt/desktop/automation_*`, `cerf-qt/automation_option.{h,cpp}`, `cerf-qt/shutdown_execution.{h,cpp}` and `bundled/tools/cerf_automation/`.
