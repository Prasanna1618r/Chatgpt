    stage('Build App') {
            when {
                expression { return params.BRANCH?.trim() }
            }
            agent { label 'windowsbuilder.mitsogo.com'}

            steps {

                /*===============================
                 Cleaning workspace before build
                ===============================*/
                script {
                    echo "Cleaning workspace..."
                    deleteDir()
                }

            
                /*================
                 Build Dependency 
                ================*/
                withCredentials([
                    file(credentialsId: 'JENKINS_AWS_CREDENTIALS', variable: 'AWS_SHARED_CREDENTIALS_FILE'), 
                    string(credentialsId: 'gitpassstring', variable: 'GIT_PASSWORD'),
                    ]) {

                    powershell '''
                        $value = ${env:BRANCH}
                        $env:BUILD_NUMBER = $env:BUILD_VERSION
                        $tempdir = $env:BUILD_TIMESTAMP
                        new-item -type directory $tempdir
                        $Env:PATH = "C:\\Users\\devops\\AppData\\Roaming\\nvm\\;C:\\Program Files\\nodejs\\;C:\\Hexnode-Builder\\python-env\\Scripts\\;" + $Env:PATH
                        $Env:PATH += ";C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin" 
                        $Env:PATH = "C:\\Users\\Devops\\AppData\\Roaming\\nvm\\v" + $env:NODE_VERSION + "\\;" + $Env:PATH
                        $Env:PATH
                        $S3_BASE = "s3://testing-hexnode/jenkins/$ENV:JOB_NAME/$ENV:BUILD_ID"
                        
                        function message {
                            param ( [string]$message )
                            Write-Output "`n[ $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") $env:COMPUTERNAME] $message"
                        }
                        
                        
                        message "info: checking node version $env:NODE_VERSION is available in this node."
                        $nodeVersions = Get-ChildItem -Path "C:\\Users\\Devops\\AppData\\Roaming\\nvm\\" -Directory | Where-Object { $_.Name -match \'^v\\d+\\.\\d+\\.\\d+$\' } | ForEach-Object { $_.Name -replace \'^v\', \'\' }
                        if ($nodeVersions -contains $env:NODE_VERSION) {
                            message "info: node version $env:NODE_VERSION is available."
                        } else {
                            message "info: node version $env:NODE_VERSION is not available."
                            exit 1
                        }
                        
                        
                        Set-Location $tempdir
                        message "info: current working dir is: $(pwd)"
                        
                        
                        message "info: cloning macosuiagent repository"
                        git.exe clone https://devops-team:${env:GIT_PASSWORD}@gitlab.mitsogo.com/desktopuiapps/macosuiagent
                        $TMPExitCode = $LASTEXITCODE
                        If ($TMPExitCode -ne 0) {
                             message "critical: error while cloning git repo."
                             Exit $TMPExitCode
                        }
                        message "info: repo successfully cloned, changed to macosuiagent directory"
                        Set-Location macosuiagent
                          
                        
                       
                        $existed_in_remote= git.exe ls-remote --heads origin $value 
                        if ($existed_in_remote) { 
                            Write-Output  $existed_in_remote 
                            git.exe checkout $value 
                        }
                        else {
                          	message "critical: branch $value does not exist"
                            Exit 
                        }
                        
                        message "info: getting version info from package.json file"
                        try{
                            $x = Get-Content -Path ".\\package.json" -ErrorAction Stop | ConvertFrom-Json
                        }
                        catch {
                            Write-Output "`nError Message: " $_.Exception.Message
                            Write-Output "`nError in Line: " $_.InvocationInfo.Line
                            Write-Output "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber
                            Write-Output "`nError Item Name: "$_.Exception.ItemName
                            Exit
                        }
                        
                        
                        $applicationname = "Hexnode UEM Setup {0}.exe" -f $x.version
                        message "info: application name is $applicationname"
                        
                        
                        message "info: printing node version"
                        node -v
                        
                        
                        message "info: installing npm packages"
                        npm install
                        $NPMExitCode = $LASTEXITCODE
                        If ($NPMExitCode -ne 0) {
                             message "critical: error while installing project packages and dependencies"
                             Exit $NPMExitCode
                        }
                        message "info: installed all the project packages and dependencies"
                        
                        
                        # message "info: exporting signing certificate and signing password "
                        # $Env:CSC_LINK = "C:\\Hexnode-Builder\\resource\\mitsogoinc_codesigning.p12"
                        # $Env:CSC_KEY_PASSWORD = $Env:SIGNPASSWORD
                        $Env:ELECTRON_BUILDER_CACHE = $tempdir
                        
                        
                        message "info: creating windows pacakge"
                        npm run pack.windows
                        $PACKExitCode = $LASTEXITCODE
                        If ($PACKExitCode -ne 0) {
                             message "critical: error while running pack.windows"
                             Exit $PACKExitCode
                        }
                        message "info: BUILD SUCCESSFUL..!"
                        
                        
                        $path1 = ".\\dist\\win-unpacked\\Hexnode UEM.exe"
                        $path2 = ".\\dist\\win-ia32-unpacked\\Hexnode UEM.exe"
                        $win_unpacked = if (Test-Path $path1) { $path1 } else { $path2 }
                        
                        
                        message "info: uploading unsigned file: $win_unpacked to s3..."
                        aws s3 cp "$win_unpacked" "$S3_BASE/$tempdir/win-unpacked/Hexnode UEM.exe" --region eu-central-1 --no-progress --profile testing-hexnode
                        $AWSExitCode = $LASTEXITCODE
                        If ($AWSExitCode -ne 0) {
                             message "critical: error while uploading the executable file to S3"
                             Exit $AWSExitCode
                        }
                        
                        
                        
                        message "info: signing file: $win_unpacked in job: WINDOWS_APP_SIGNING"'''
                }

                /*==================
                 Signing Dependency
                ===================*/
                script {
                    build job: 'TEST_DEPLOY_WINDOWS_SIGN_APP', parameters: [
                        string(name: 'S3_URL',           value: "\"s3://testing-hexnode/jenkins/$JOB_NAME/$BUILD_ID/$BUILD_TIMESTAMP/win-unpacked/Hexnode UEM.exe\""),
                        string(name: 'FILE_NAME',        value: "Hexnode UEM.exe")
                    ]
                }
            }
