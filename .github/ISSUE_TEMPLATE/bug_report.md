---
name: Bug report
about: Found something broken for a specific device?
title: '[DEVICE NAME] - Crash when playing WMP music and doing parallel work'
labels: bug, enhancement
assignees: dz333n
type: Bug

---

### **Describe the bug**

Thank for reporting a bug. Please, fill all the information on this ticket matching the example patterns. Replace this text with concise bug description if a title doesn't work alone. Don't touch the sample text (or just remove it) if the section doesn't matter in your opinion. Start with the ticket title - keep it concise and distinct. Write a device name in it if its applicable to a specific device.

### Complete this section if its applicable to a device or remove this section
- ROM obtained from known public reposiry?
  - [x] yes
  - [ ] no
- Could you share the ROM for testing?
  - [x] not needed - it's reproducible on other known ROMs of this device family - developer can just boot any and reproduce
  - [ ] not needed - available online for download (``ROM NAME OR DESCRIPTION so we know which one it is``)
  - [ ] yes
- Did you use Guest Additions:
  - [x] no
  - [ ] yes
- Emulator build  (in window caption or in about dialog):
  - ``build 700``
- Host OS:
  - [x] doesn't matter, i feel this is emulation bug rather then host implementation bug
  - [ ] ``Windows 11 build 26200``
- [optional] Did you access the feature that is marked unsupported on the "Unsupported" panel when you open device details?
  - [ ] yes, it is unsupported, but it is demanded, me or other people would enjoy it
  - [ ] yes, it is unsupported, and now i think it's not really demanded so i stoppped writing this ticket
  - [ ] no, it is not there and I expected it to be supported

### **To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

### **Expected behavior**
A clear and concise description of what you expected to happen, if it's applicable.

### **Screenshots**
If applicable, add screenshots to help explain your problem.

### **Attachments**
If you are describing a crash, include CERF log files. Locate ``cerf.log`` and ``cerf.crash.log`` in your CERF installation directory. You can skip this if you believe it's easy to reproduce. Your log files will include personal data like user directory names, hardware configuration, etc. If it's a device manager crash, attach ``manager.log`` too.
