---
name: bad
description: Course correction when the approach of the agent is bad, either a stop without a reason or work that goes the wrong way.
---

# /bad - your approach is bad. Restart it.

What you are doing is bad. Either you stopped work that had a clear next step, or you continued to work the wrong way. Do these steps in this reply, in this order.

1. Stop the approach. Do not finish the step that you were on. Do not defend it.
2. Say what you did wrong. Give each wrong action with its turn, the quoted text or the file and line, and the rule that it broke. If you stopped, quote the sentence where you stopped. Also list each bug or rule violation in your earlier work that you did not disclose. "I lost focus" and "I made mistakes" are not items.
3. Say how you will prevent it. For each item, name the action that replaces it, for example "paste the datasheet entry before I write the handler", "add a hook, not a list of hypotheses", or "run the next step, not a question". "I will be more careful" is not an action.
4. Repair the damage. If you deleted or reverted work, restore it from your own earlier Write and Edit calls. Do not ask first. Revert the uncommitted code of the bad approach. If you already committed a bad change, name that commit in a question to the user.
5. Restart from the task. Quote the task as the user gave it. Find the last concrete artifact from a tool call: a log line, a decompiled function, a hook fire, or a file that you read. Your own analysis is not an artifact. From that artifact, name the next mechanical step. The new approach must not be the old approach under a new name.
6. Do that step in this reply. Then continue. Do not ask whether to continue. If a decision belongs to the user, end the reply with one specific question about it.

The reply has no apology, no "you're right", no option list, and no plan that waits for approval.
