Set-ExecutionPolicy RemoteSigned 

$TARGET_DIR = "HOME\Downloads"

$files = Get-ChildItem -Path $TARGET_DIR -File

foreach($file in $files){

$extension = $file.Extension.ToLower().TrimStart(".")

switch($extension){
"jpg" { $folder = "Images"}
"png" { $folder = "Images"}
"jpeg" { $folder = "Images"}

"pdf" { $folder = "Docs"}
"docx" {$folder = "Word_Docs"}
"txt" {$folder = "Text_Docs" }

"mp3" { $folder = "Audios"}
"wav" { $folder = "Wave_Audios"}
"exe" { $folder = "executabbles"}

default { $folder = "Others"}
}

$destination - Join-Path $TARGET_DIR $folder
New-Item -ItemType Directory -Path $destination -Force | Out-Null

Move_Item -PAth $file.FullName -Destination $destination

$log= "$TARGET_DIR\organized.log"
$message = "Moved $($file.Name) to $folder"

Add-Content -Path $log -Value $messgae
Write-Output $messgage 
}


