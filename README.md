<img src="docs/github_band.svg" width="100%"/>

<div align="center">
  <b>CE Runtime Foundation</b> (aka <i>CERF</I>) - <b>Universal Windows CE emulator</b><br/>
  <b><a href="https://cerf.cx">cerf.cx</a></b> - read more information about the project  
</div><br/>

<div align="center">
  <a href="https://discord.gg/QREE9Y2v2d"><img src="https://img.shields.io/badge/Discord-join%20the%20server-5865F2?logo=discord&amp;logoColor=white" alt="Discord"/></a> <a href="https://www.patreon.com/dz3n"><img src="https://img.shields.io/badge/Patreon-support-FF424D?logo=patreon&amp;logoColor=white" alt="Patreon"/></a>
</div>

<br/>

> [!WARNING]
> **Beta stage.** CERF is a hobby project, developed in spare time
> and can't be a called production-grade/exceptionally stable project.
> **Expect bugs, crashes, and breaking changes.** 🙃
>
> For the same reason - be careful if you are going to use CERF is a reference for
> hardware level behaviour. The code works but CERF is not an official chip datasheet.

## Downloads

To use the newest features, download the WIP build (7.0) from the artifacts [![build](https://github.com/gweslab/cerf/actions/workflows/build.yml/badge.svg)](https://github.com/gweslab/cerf/actions/workflows/build.yml). For a stable version, go to the [latest release](https://github.com/gweslab/cerf/releases/latest).

If you need any additional help, e.g. what to run and how to use the emulator - visit [cerf.cx](https://cerf.cx/articles).

See ``cerf.exe`` command line usage at [cerf.cx/articles/command-line](https://cerf.cx/articles/command-line/).

## Supported boards

<table>
  <thead>
    <tr>
      <th>SoC</th>
      <th>Board / OS</th>
      <th>Features</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>NEC VR4111</b><br/><sub>MIPS III</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Casio Cassiopeia E-55</b> <code>casio_cassiopeia_e55</code><br/>
        Palm-size PC
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/serial_com.svg" width="32" height="32" title="Serial Port" alt="Serial Port"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>NEC VR4122</b><br/><sub>MIPS III</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Casio Cassiopeia EM-500</b> <code>casio_cassiopeia_em500</code><br/>
        Pocket PC 2000
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>NEC VR4121</b><br/><sub>MIPS III</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Casio Toricomail / Message-Cam / Pocket PostPet</b> <code>casio_toricomail</code><br/>
        Windows CE 2.12
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/></td>
    </tr>
    <tr>
      <td rowspan="2" align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Intel XScale PXA255</b><br/><sub>ARMv5TE</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Falcon 4220</b> <code>falcon_4220</code><br/>
        Windows CE .NET
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/></td>
    </tr>
    <tr>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>NEC MobilePro 900</b> <code>nec_mobilepro_900</code><br/>
        Handheld PC 2000<br/>
        Windows CE .NET
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Freescale i.MX51</b><br/><sub>Cortex-A8</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Ford SYNC 2</b> <code>ford_sync_2</code><br/>
        Windows Embedded CE 6
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/></td>
    </tr>
    <tr>
      <td rowspan="4" align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Intel SA-1110</b><br/><sub>StrongARM</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>HP Jornada 720</b> <code>jornada_720</code><br/>
        Handheld PC 2000<br/>
        Linux
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/></td>
    </tr>
    <tr>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>iPAQ H3100/H3600/H3700</b> <code>ipaq_gen1</code><br/>
        Pocket PC 2000<br/>
        Pocket PC 2002
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/microphone.svg" width="32" height="32" title="Microphone" alt="Microphone"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/></td>
    </tr>
    <tr>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Siemens SIMpad SL4</b> <code>simpad_sl4</code><br/>
        Handheld PC 2000<br/>
        Windows CE .NET
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/></td>
    </tr>
    <tr>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>SmartBook G138</b> <code>smartbook_g138</code><br/>
        Windows CE .NET
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Intel SA-1100</b><br/><sub>StrongARM</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>HP Jornada 820</b> <code>jornada_820</code><br/>
        Handheld PC 3.0 Professional
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/cursor.svg" width="32" height="32" title="Mouse" alt="Mouse"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>ARM720T</b><br/><sub>ARMv4T</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Microsoft Windows CE Hardware Reference Platform</b> <code>odo</code><br/>
        Windows CE 2.11<br/>
        Windows CE 3
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>NEC VR4102</b><br/><sub>MIPS III</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>NEC MobilePro 700</b> <code>nec_mobilepro_700</code><br/>
        Windows CE 2.0
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/serial_com.svg" width="32" height="32" title="Serial Port" alt="Serial Port"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>NEC VR5500</b><br/><sub>MIPS IV</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>NEC Rockhopper SG2_VR5500</b> <code>nec_rockhopper</code><br/>
        Windows Embedded CE 6
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/cursor.svg" width="32" height="32" title="Mouse" alt="Mouse"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>TI OMAP 3530</b><br/><sub>Cortex-A8</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>OMAP 3530 EVM</b> <code>omap_3530_evm</code><br/>
        Windows Embedded Compact 7<br/>
        Windows Embedded Compact 2013
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/></td>
    </tr>
    <tr>
      <td rowspan="2" align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>Philips PR31700</b><br/><sub>MIPS I</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Philips Nino 300</b> <code>philips_nino_300</code><br/>
        Palm-size PC
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/> <img src="cerf/assets/icons_sources/serial_com.svg" width="32" height="32" title="Serial Port" alt="Serial Port"/></td>
    </tr>
    <tr>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Sharp Mobilon HC-4100</b> <code>sharp_mobilon_hc4100</code><br/>
        Windows CE 2.0
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/> <img src="cerf/assets/icons_sources/serial_com.svg" width="32" height="32" title="Serial Port" alt="Serial Port"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_mips.png" align="middle" title="MIPS" alt="MIPS"/><br/><b>Philips PR31500</b><br/><sub>MIPS I</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Philips Velo 1</b> <code>philips_velo_1</code><br/>
        Windows CE 1.0
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/> <img src="cerf/assets/icons_sources/serial_com.svg" width="32" height="32" title="Serial Port" alt="Serial Port"/></td>
    </tr>
    <tr>
      <td rowspan="2" align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Samsung S3C2410</b><br/><sub>ARM920T</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Siemens P177</b> <code>siemens_p177</code><br/>
        Windows CE 5
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/></td>
    </tr>
    <tr>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Device Emulator</b> <code>devemu</code><br/>
        Windows Embedded CE 6<br/>
        Windows Mobile 5<br/>
        Windows Mobile 6<br/>
        Windows Mobile 2003 SE<br/>
        Windows CE 5
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/suspend.svg" width="32" height="32" title="Suspend / Resume" alt="Suspend / Resume"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/> <img src="cerf/assets/icons_sources/pcmcia_enabled.svg" width="32" height="32" title="PCMCIA" alt="PCMCIA"/> <img src="cerf/assets/icons_sources/internet.svg" width="32" height="32" title="Network" alt="Network"/> <img src="cerf/assets/icons_sources/battery.svg" width="32" height="32" title="Battery" alt="Battery"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Intel XScale PXA270</b><br/><sub>ARMv5TE</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Symbol MK500</b> <code>symbol_mk500</code><br/>
        Windows CE 5
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/stylus.svg" width="32" height="32" title="Touch" alt="Touch"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/></td>
    </tr>
    <tr>
      <td align="center"><img src="launcher/assets/icons/badge_arm.png" align="middle" title="ARM" alt="ARM"/><br/><b>Freescale i.MX31L</b><br/><sub>ARM1136</sub></td>
      <td>
        <img src="cerf/assets/icons_sources/board.svg" width="16" height="16" title="PDA" alt="PDA"/> <b>Zune 30</b> <code>zune_30</code><br/>
        Windows CE 5
      </td>
      <td><img src="cerf/assets/icons_sources/display.svg" width="32" height="32" title="Display" alt="Display"/> <img src="cerf/assets/icons_sources/keyboard.svg" width="32" height="32" title="Keyboard" alt="Keyboard"/> <img src="cerf/assets/icons_sources/ga_autoresize.svg" width="32" height="32" title="Guest Additions" alt="Guest Additions"/> <img src="cerf/assets/icons_sources/speaker_active.svg" width="32" height="32" title="Sound" alt="Sound"/></td>
    </tr>
  </tbody>
</table>

## Running your own ROM

A ROM boots only if **CERF implements that exact board**. A matching SoC is not sufficient.

**The board is on the supported list.** The [articles](https://cerf.cx/articles/own-rom/) show how to boot your own dump.

**The board is not on the supported list.** A new board is a code contribution. It needs C++ for the memory map of the board, for each peripheral that the drivers use, and for the quirks of the SoC. The code must agree with datasheets, BSP sources and reverse engineering, at the quality level of the current tree. A new board is not a change to a configuration file - that's not that simple.

> [!IMPORTANT]
> **CERF does not accept ROM submissions or requests for new boards.** If you want a new board - your only choice is to build a support yourself and send a contribution.

## Building

CERF requires Visual Studio 2026 with the C++ desktop development workload.

> [!NOTE]
> **The first build on a new machine takes more than one hour.** vcpkg compiles the dependencies from source before CERF links. This occurs one time on each machine. Later builds use the cached `vcpkg_installed/` tree and are complete in a few minutes. Do not stop the first build.

Configure the clone (one time on each machine):

```
setup.cmd
```

or dry run:

```
setup.cmd -Check
```

It will
- point git at tracked hooks
- report missing prerequisite

**Build the entire proejct with a helper script**:

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

The script will:
- wait for a parallel build (Claude Code-special feature for parallel agents work)
- build the launcher (and will install CPython into a repo directory, if needed)
- build the emulator itself (and will pick appropriate SDK/toolchain from your installations)
- build all the bundled Windows CE apps (at ``ce_apps/``)

### Building the CE-side binaries (optional)

`ce_apps/` holds the Windows CE binaries that CERF ships, and the Guest Additions driver.
To build them, you need a CE toolchain and a CE SDK. 

`cerf.exe` does **not** need them. If you work on the emulator core, the boards, the SoCs, the JIT or the host UI,
use the prebuilt binaries from another CERF release or just dont use them at all.

To build `ce_apps/`, install eMbedded Visual C++ 4.0 (a free Microsoft download from the
Microsoft archive). CERF includes a script that will unpack the installation (you dont want and probably can't install ancient tools)
and will place the build tools / SDK into appropriate directories.
See **[docs/ce_apps_setup.md](docs/ce_apps_setup.md)**.

`setup.cmd -Check` reports whether the CE toolchain is present.

### Website

This repositroy includes [cerf.cx](https://cerf.cx) source code at ``docs/website``.

`python tools/build_site.py --serve` runs the website on your machine with live reload.

## Changelog

<table>
  <thead>
    <tr>
      <th>Version</th>
      <th>Release Date</th>
      <th>Changes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>v7.0</td>
      <td>TBA</td>
      <td>
        <p><b>📱 Devices</b><br/>
          🆕 Casio Cassiopeia E-55 support<br/>
          🆕 Symbol Mk500 support<br/>
          🆕 Casio Toricomail: bezel touch buttons<br/>
          ✅ Philips Velo 1: 16 MB DRAM Miniature Card permanently fitted - 20 MB total for the guest<br/>
          ✅ Device Emulator: keyboard no longer drops or repeats keys while typing<br/>
          ✅ Device Emulator: sound no longer stutters<br/>
          ✅ Device Emulator: Windows Mobile 2003 SE no longer freezes<br/>
          ✅ Casio Toricomail: fixed rendering crashes</p>
        <p><b>💿 Emulator</b><br/>
          🆕 Configurable display colour depth for Guest Additions and Device Emulator<br/>
          🆕 Bundled CompactFlash cards can be auto-inserted at launch<br/>
          🆕 Build number shown in the window title and the About box<br/>
          🆕 Thumb32 support. Windows Embedded Compact 2013 is now supported<br/>
          🆕 Host key is now reassignable<br/>
          🆕 Right Click simulation mode for the stock stylus (synths LAlt+Tap)<br/>
          ✅ ARM JIT and JIT core full rewrite. ARM JIT/peripherals massive optimizations. However - this might regress something, the blast radius is whole ARM emulation.<br/>
          ✅ Wall-clock timer instead of icount. Fixes guest OS clock extreme fast forwarding and consequent lags, bugs. For example, Jornada 720 had whole class of problems. Double clicks wouldn&#x27;t work because whole days passed in between two clicks. IE would time out on the same reason. Our model is based on QEMU and Dolphin models with own inventions.<br/>
          ✅ Shutdown dialog now has reboot options<br/>
          ✅ Media instructions for Zune 30</p>
        <p><b>🚀 Launcher</b><br/>
          🆕 Copyright removal dialog listing each bundle repository&#x27;s abuse contact, reachable from the Download ROMs window and the download confirmation<br/>
          🆕 GitHub issues window (Bugs&amp;Requests)<br/>
          🆕 Update channel setting: disable updates, stable releases, or unstable CI builds<br/>
          ✅ Installed devices are listed and launchable immediately at startup instead of waiting for the bundle catalog on a slow or absent connection<br/>
          ✅ Toolbar buttons that no longer fit a narrow window move into a chevron menu instead of being cut off<br/>
          ✅ The update check now understands build numbers in release tags</p>
        <p><b>✨ Guest Additions</b><br/>
          🆕 Share folder settings and Guest Additions customizations are now unified with launcher UI and persisted even when changed at runtime<br/>
          🆕 Windows CE 2013 support<br/>
          🆕 Font size override support<br/>
          🆕 Stylus simulation mode for the mouse pointer<br/>
          ✅ Splash animations (stock framebuffer) are now displayed under guest additions mode too (stock framebuffer is displayed until GA framebuffer is used). Input source is now stock until user-space library has accessed virtual IO. This fully fixes, for example, the Jornada RAM erase screen. It is now visible, it is now interactable without any additional manipulations.<br/>
          ✅ Crash when drawing off-screen (GiNi)<br/>
          ✅ Default colour depth is now 24bpp instead of 32bpp - fixes Device Emulator Windows Mobile 6.5 shell rendering<br/>
          ✅ Colour corruption in 16bpp mode - alpha-blended elements rendered green/cyan<br/>
          ✅ Gradients on Windows CE 4 - the taskbar and application backgrounds render again<br/>
          ✅ Mouse and keyboard no longer stop working for the whole session when input arrives early during boot<br/>
          ✅ Crash/artifacts when scrolling under complex rendering</p>
      </td>
    </tr>
    <tr>
      <td>v6.7</td>
      <td>23 Jul 2026</td>
      <td>
        <p><b>📱 Devices</b><br/>
          🆕 Casio Cassiopeia EM-500 support (bare bones)<br/>
          ✅ Sharp Mobilon HC-4100: fixed suspend crash</p>
        <p><b>💿 Emulator</b><br/>
          🆕 Discord Rich Presence - shows the current device and OS in your Discord profile<br/>
          🆕 UI updates<br/>
          ✅ Fixed framebuffer not relatching on suspend/resume<br/>
          ✅ Fixed 100% CPU usage and UI deadlocks on Windows XP on non-framebuffer tabs</p>
        <p><b>🚀 Launcher</b><br/>
          🆕 UI refresh<br/>
          ✅ Metadata-only remote updates no longer re-download the entire ROM<br/>
          ✅ Fixed the command-line interface producing no output<br/>
          ✅ Configuration, updates and removal are now blocked while a device is running<br/>
          ✅ Single click on a device preview now launches it everywhere<br/>
          ✅ Merged the two launcher builds into a single Windows Vista+ executable<br/>
          ❌ Removed the redundant soc_family and board_name fields from cerf.json</p>
        <p><b>💾 CE Apps</b><br/>
          ✅ CerfDemo: UI and performance improvements</p>
        <p><b>✨ Guest Additions</b><br/>
          🆕 High refresh rate support - use Windows CE with 240 hz display! (Or whatever Hz you have). Yes, this should be taken LITERALLY. WinCE WILL render 240 fps on your 240 hz monitor. The guest video mode and host window scanout follow the host monitor&#x27;s refresh rate<br/>
          🆕 --screen-refresh-rate flag to set the refresh rate manually<br/>
          🆕 Touch-calibration helper - offers to switch to the stock input device when the guest opens a calibration screen, and switches back afterwards<br/>
          🆕 Color scheme overrides - colorize grayscale devices with a forced system color scheme<br/>
          ✅ Input devices now run at the proper priority, staying responsive under heavy guest CPU load</p>
      </td>
    </tr>
    <tr>
      <td colspan="3"><b>Previous versions</b> - see the <a href="https://cerf.cx/changelog/">full changelog</a>.</td>
    </tr>
  </tbody>
</table>

## Known Issues

For the issues of each board, see the [board database of the launcher](launcher/supported_devices.py) or read Notes block when you use a launcher.

## Claude Development Environment

> [!TIP]
> Contributions made with AI are welcome - only if they correspond the quality level we maintain. The development involves a huge **human resouce** contribution. Do not turn this project into AI slop - we build a respectable emulator here.

The environment includes several contraversional things you need to know before using it.

- Full project **documentation is injected** into a system prompt - this eats tokens
- The environment **kills** global ``clangd.exe`` and own ``claude.exe`` instances if they leak memory
- Thinking is set to *high*; **bypass permissions mode** is set
- Several own/3rd-party **skills** included
- Powerful hooks triggering when agent might do something bad to the codebase
- IDA MCP is ready to be installed at ``tools\ida_server.py`` and ``tools\ida_claude.py``
- FS Read MCP is a workaround for ``Read()`` tool, useful for ``/tracking restore`` and massive text files (``tools\fs_read_mcp.py``)

The environment gives you the **`/start-board-implementation`** skill. Run the skill and agent will start the new board bring-up on its own. You need experience - the skill won't do all the work instead of you. (Tho honestly speaking, there have been cases where Claude alone brought a board to a bootable state)

Run the environment:

```
run_claude.cmd
```

## License

[MIT](LICENSE). Third-party components and studied references are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

CERF was started as [WCECL](https://github.com/dz333n/wcecl) in 2019.

**Copyright (c) 2019-2026 [Yaroslav Kibysh](https://yaroslavkibysh.com)**
