# Get Datto RMM Tool process

$process = get-process -name "gui" -ErrorAction SilentlyContinue
if ($process) {
    write-output "Datto RMM tool running, exiting"
    exit 0
}
else {
    exit 1
}