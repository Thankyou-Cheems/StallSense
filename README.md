# Windows idle freeze troubleshooting guide (no display, high power, instant power-off)

Symptoms that match this guide:
- After long idle time the screen stays black or never wakes
- Fans keep spinning / power draw stays high
- Keyboard/mouse do not respond
- A short power-button press cuts power immediately

Likely root cause (when it only happens after long idle):
- Power management + GPU/driver hang during idle resume
- This is a system-level hang, not a normal "slow" freeze

---

## 1) Quick confirmation (10 minutes)

### 1.1 Event Viewer
Open Event Viewer -> Windows Logs -> System, check around the crash time:
- Kernel-Power 41 (unexpected shutdown)
- Display / nvlddmkm / amdkmdag
- WHEA-Logger

If a GPU driver error appears just before Kernel-Power 41, it strongly indicates a GPU resume hang.

### 1.2 Confirm the trigger
If it only happens after long idle / lock screen, focus on power-management fixes.

---

## 2) Highest impact fixes (do in order)

### 2.1 Temporarily disable idle sleep (to verify the cause)
Settings -> System -> Power & Sleep:
- Screen: Never
- Sleep: Never

If the problem disappears, the power-management path is the culprit.

### 2.2 Disable PCIe power saving (key step)
Control Panel -> Power Options -> Change plan settings -> Advanced power settings:
- PCI Express -> Link State Power Management: Off
- Hard disk -> Turn off hard disk after: Never
- Processor power management -> Minimum processor state: 5% to 10%

### 2.3 GPU power policy
NVIDIA Control Panel -> Manage 3D settings (Global):
- Power management mode: Prefer maximum performance
- Low latency mode: Off during testing

AMD: set the driver power profile to High Performance / Stable.

### 2.4 Disable Fast Startup
Control Panel -> Power Options -> Choose what the power buttons do:
- Uncheck "Turn on fast startup"

---

## 3) If it still happens

### 3.1 Driver rollback / update (use stable official driver)
- Avoid Windows auto-installed drivers
- Avoid beta drivers

### 3.2 BIOS / chipset update
- Use stable versions from your motherboard or laptop vendor

### 3.3 Memory / power stability (desktop focus)
- Temporarily disable XMP
- Reseat GPU and PCIe power cables
- Check PSU quality/aging

---

## 4) Verify the fix
1. Apply the steps in section 2
2. Leave the PC idle for 1-2 hours
3. Try to wake it

Result:
- Wakes normally: fixed
- Still hangs: continue with section 3

---

## 5) Info that helps me pin it down
- Desktop or laptop?
- CPU + GPU model
- Multi-monitor or hybrid graphics?
- Any recent driver/Windows major update?

If you want, I can provide a device-specific stable configuration based on your GPU model.
