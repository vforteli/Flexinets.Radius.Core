param($installPath, $toolsPath, $package, $project)

$configItem = $project.ProjectItems.Item("radius.dictionary")

# set 'Copy To Output Directory' to 'Copy if newer'
$copyToOutput = $configItem.Properties.Item("CopyToOutputDirectory")

# Copy Always Always copyToOutput.Value = 1
# Copy if Newer copyToOutput.Value = 2  
$copyToOutput.Value = 2

# set 'Build Action' to 'Content'
$buildAction = $configItem.Properties.Item("BuildAction")
$buildAction.Value = 2