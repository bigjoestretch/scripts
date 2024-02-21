$process = get-process -name "Gui"
if ($process) {
    write-output "Datto RMM gui.exe detected, exiting"
    exit 0
}
else {
    exit 1
}