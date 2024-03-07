# Get-EspDetectionOption
This requirement script (used as a requirement for the UpdateOS Windows Update Intune app) checks a device
to see if the if defaultuser0 or defaultuser1 user account exists on a machine.

If the user account exists, then the UpdateOS app runs and checks and applies any available Windows Updates
to the machine during the Windows Autopilot ESP phase (during the technician phase). These user accounts only
exist during the Windows Autopilot ESP phase, so the UpdateOS Intune app will only run during Autopilot, and
not normally on every machine.
