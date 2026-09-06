# SYNC 2 USB identity evidence

## Hardware capture

These excerpts are from the owner's real-device `MsgLog2.txt` and
`cerf_sync2diag.txt` dump, inspected on 2026-09-05. Unrelated vehicle and
Bluetooth records are omitted.

```text
144941  USB!AttachDevice: VID:PID:BCD 0424:2640:08a2 (1060_9792_2210)
145536  USB!AttachDevice: VID:PID:BCD 0424:4040:0203 (1060_16448_515)
163848  USB!AttachDevice: VID:PID:BCD 13fe:6400:0100 (5118_25600_256)
```

The first device is the Media Hub, the second its SD reader, and the third
the USB disk plugged into the external port. The USB disk's identity is
that captured accessory, not an identity common to all USB disks.

The live registry dump contains:

```text
HKLM\System\StorageManager\Profiles\USBSDProfile
SDcard_PID_2 (DWORD) = 0x00004040
SDcard_VID_2 (DWORD) = 0x00000424
SDcard_PID_1 (DWORD) = 0x00002240
SDcard_VID_1 (DWORD) = 0x00000424
SDcard_PID_0 (DWORD) = 0x00002640
SDcard_VID_0 (DWORD) = 0x00000424
Folder (string) = SDMemory
Name (string) = USB SD Drive
```

The extracted SYNC 2 guest's AUTOUSBDISK6.DLL (MD5
`06d916866a1b3097e6ba3855073cfdf8`) `UsbDiskAttach`
at `0xC05E4FEC` passes the device VID/PID to the registry matcher at
`0xC05E2C78`. Its SD classification therefore depends on USB identity,
not just the mass-storage interface class.

## INQUIRY

The same guest DLL's routine at `0xC05E5ADC` issues a 36-byte INQUIRY.
After a successful transfer it checks byte 0, stores the peripheral-device
type from that byte and the removable-media bit from byte 1, and discards
the remaining response. It does not retain or compare the vendor, product,
or revision strings.

CERF's INQUIRY strings remain synthetic. This verifies their lack of use
in the inspected attachment routine, not every possible application or
SCSI pass-through consumer. The hardware logs above do not capture real
INQUIRY strings or a complete descriptor set; they are not evidence of
full USB2640 reader emulation.
