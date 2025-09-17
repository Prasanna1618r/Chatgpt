pipeline {
    agent none
    
    environment {
        BUILD_TIMESTAMP = "${new Date().format('yyyyMMddHHmmss')}"
        APP_NAME = "authenticator"
    }

    stages {
        
        stage('Build') {
            when {
                expression { return params.BRANCH?.trim() }
            }
            agent {label 'windowsbuilder.mitsogo.com'}
            steps {
                
                /*=====================
                 Building Updater App
                =======================*/
                withCredentials([string(credentialsId: 'gitpassstring', variable: 'GIT_PASSWORD'), string(credentialsId: 'windows_installer_signin', variable: 'SIGNPASSWORD'), string(credentialsId: 'jenkins_proxy', variable: 'https_proxy'), file(credentialsId: 'JENKINS_AWS_CREDENTIALS', variable: 'AWS_SHARED_CREDENTIALS_FILE')]) {
                    script{
                        def output = powershell(returnStdout: true, script: '''
                            $value = ${env:BRANCH}
                            
                            $env:BUILD_NUMBER = $env:BUILD_VERSION
                            
                            $tempdir = $env:BUILD_TIMESTAMP
                            New-Item -Type Directory $tempdir
                            
                            $Env:PATH = "C:\\Users\\devops\\AppData\\Roaming\\nvm\\;C:\\Program Files\\nodejs\\;C:\\Hexnode-Builder\\python-env\\Scripts\\;" + $Env:PATH
                            $Env:PATH += ";C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin"
                            $Env:PATH = "C:\\Users\\devops\\AppData\\Roaming\\nvm\\v" + $env:NODE_VERSION + "\\;" + $Env:PATH
                            $Env:PATH
                            
                            function message {
                                param ( [string]$message )
                                Write-Output "`n[ $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") $env:COMPUTERNAME] $message"
                            }
                            
                            Set-Location $tempdir
                            message "info: current working dir is: $(pwd)"
                            
                            message "info: cloning windowshexauthenticator repository"
                            git.exe clone https://devops-team:${env:GIT_PASSWORD}@gitlab.mitsogo.com/windowsapplication/windowshexauthenticator
                            $TMPExitCode = $LASTEXITCODE
                            If ($TMPExitCode -ne 0) {
                                 message "critical: error while cloning git repo."
                                 Exit $TMPExitCode
                            }
                            
                            message "info: repo successfully cloned, changed to windowshexauthenticator directory"
                            Set-Location windowshexauthenticator
                            
                            
                            $existed_in_remote = git.exe ls-remote --heads origin $value
                            
                            if ($existed_in_remote) {
                                Write-Output $existed_in_remote
                                git.exe checkout $value
                            }
                            else {
                                message "critical: branch $value does not exist"
                                Exit
                            }
                            
                            
                            if ([string]::IsNullOrEmpty($env:FILEVERSION)) {
                                message "info: The FILEVERSION not provided."
                            } else {
                                message "info: setting up FILEVERSION - $env:FILEVERSION"
                                (Get-Content "package.json") -replace \'"version":\\s*".*?"\', "`"version`": `"$env:FILEVERSION`"" | 
                                Set-Content ".\\package.json"
                            }
                            message "info: getting version info from package.json file"
                            try {
                                $x = Get-Content -Path ".\\package.json" -ErrorAction Stop | ConvertFrom-Json
                                $VERSION = $x.version
                            }
                            catch {
                                Write-Output "`nError Message: " $_.Exception.Message
                                Write-Output "`nError in Line: " $_.InvocationInfo.Line
                                Write-Output "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber
                                Write-Output "`nError Item Name: "$_.Exception.ItemName
                                Exit
                            }
                            
                            $applicationname = "Hexnode Authenticator Setup {0}.exe" -f $x.version
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
                            
                            $Env:ELECTRON_BUILDER_CACHE = $tempdir
                            
                            message "info: creating windows package"
                            npm run build-electron
                            
                            $PACKExitCode = $LASTEXITCODE
                            If ($PACKExitCode -ne 0) {
                                 message "critical: error while running build-electron"
                                 Exit $PACKExitCode
                            }
                            message "info: BUILD SUCCESSFUL..!"
                              
                            $path1 = ".\\dist\\win-unpacked"
                            $path2 = ".\\dist\\win-ia32-unpacked"
                            $win_unpacked = if (Test-Path $path1) { $path1 } else { $path2 }
                            
                            $sevenZipPath = "C:\\Program Files\\7-Zip\\7z.exe"
                            
                            message "info: making zip file of \'$win_unpacked\' folder"
                            Set-Location $win_unpacked
                            $zipFile = "$tempdir\\HexnodeAuthenticator.zip"
                            & $sevenZipPath a -tzip $zipFile *
                            
                            $ZIPExitCode = $LASTEXITCODE
                            If ($ZIPExitCode -ne 0) {
                                 message "critical: error while making zip file for \'$win_unpacked\' folder"
                                 Exit $ZIPExitCode
                            }
                            message "info: zip archive is available in location $zipFile"
                              
                            $hashOutput = certutil -hashfile "$zipFile" SHA256
                            $CHECKSUM = $hashOutput[1].Trim()
                              
                            # Fetching subdomain from PORTALNAME
                            $PORTAL = $env:PORTALNAME.Split(".")[0]  
                              
                            message "info: uploading ZIP file: $zipFile to s3..."
                            $S3_BASE = "s3://downloads.hexnode.com/windows-agent/beta/$PORTAL"
                            aws s3 cp "$zipFile" "$S3_BASE/HexnodeAuthenticator.zip" --profile jenkins --no-progress --acl public-read
                              
                            $AWSExitCode = $LASTEXITCODE
                            If ($AWSExitCode -ne 0) {
                                 message "critical: error while uploading the ZIP file to S3"
                                 Exit $AWSExitCode
                            }
                            
                            message "info:zip file is available in s3 location: "
                            Write-Output "https://downloads.hexnode.com/windows-agent/beta/$PORTAL/HexnodeAuthenticator.zip"
                            
                            Write-Output "VERSION_CHECK:$VERSION"
                            Write-Output "CHECKSUM_MARKER:$CHECKSUM"
                              
                            message "info: signing unsigned file: $win_unpacked"
                        ''').trim()
                        def checksumMatch = (output =~ /CHECKSUM_MARKER:(.*)/)
                        def version = (output =~ /VERSION_CHECK:(.*)/)
                        env.CHECKSUM     = checksumMatch ? checksumMatch[0][1].trim() : ""
                        env.ASSEMBLY_VERSION = version ? version[0][1].trim() : ""
                        echo "${env.CHECKSUM}"
                        echo "${env.ASSEMBLY_VERSION}"
                    }
                    
                    
                    /*===================
                    Signing Updater App
                    ====================*/
                    script {
                        def PORTAL = PORTALNAME.tokenize('.')[0]
                        build job: 'TEST_DEPLOY_WINDOWS_SIGN_APP', parameters: [
                            string(name: 'S3_URL',           value: "\"s3://downloads.hexnode.com/windows-agent/beta/$PORTAL/HexnodeAuthenticator.zip\""),
                            string(name: 'FILE_NAME',        value: "Hexnode Authenticator.exe"),
                            string(name: 'IS_S3_URL_PUBLIC', value: "True")
                        ]
                    }
                }
            }
        }
        stage('S3_URL') {
            when {
                expression { return params.S3_URL?.trim() }
            }
            agent { label 'windowsbuilder.mitsogo.com' }
            steps {
               
                
                withCredentials([
                    file(credentialsId: 'jenkins_aws_credential', variable: 'AWS_SHARED_CREDENTIALS_FILE'),
                    aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: '5a9c4af4-68a6-41f2-9e4c-e04657ea2402', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    script {
                        def s3Url = params.S3_URL?.trim()
                        if (!s3Url) {
                            error "S3_URL parameter is required."
                        }

                        bat """
                           @echo off
                           setlocal enabledelayedexpansion
                           REM Extract filename from S3 URL
                           for %%I in ("${s3Url}") do set FILENAME=%%~nxI
                           REM Display filename and download from S3
                           call :message "info: Downloading !FILENAME! from ${s3Url}"
                           aws s3 cp "${s3Url}" "!FILENAME!" --no-progress --region eu-central-1
                           if errorlevel 1 (
                               call :message "error: Failed to download from ${s3Url}"
                               exit /b 1
                           )
                           call :message "info: Download completed successfully: !FILENAME!"
                           goto :eof
                        :message
                           echo -----------------------------------------------------------------------------------------------------------------------
                           for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value') do set datetime=%%a
                           set timestamp=!datetime:~0,4!-!datetime:~4,2!-!datetime:~6,2! !datetime:~8,2!:!datetime:~10,2!:!datetime:~12,2!
                           echo [!timestamp! %NODE_NAME%] %~1
                           exit /b 0
                        """
                        script{
                            def output = powershell(returnStdout: true, script: '''
                                function message($msg) {
                                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                    $nodeName = $env:NODE_NAME
                                    Write-Host "[$timestamp $nodeName] $msg"
                                }
                            
                                message "info: Starting extraction and checksum calculation..."
                            
                                try {
                                    Expand-Archive -Path HexnodeAuthenticator.zip -DestinationPath extracted -Force
                                } catch {
                                    message "error: Failed to extract ZIP file."
                                    exit 1
                                }
                            
                                try {
                                    $zipChecksum = (Get-FileHash -Path "HexnodeAuthenticator.zip" -Algorithm SHA256).Hash
                                } catch {
                                    message "error: Failed to calculate ZIP checksum."
                                    exit 1
                                }
                            
                                $targetFile = Get-ChildItem -Path extracted -Recurse -Include *.exe | Select-Object -First 1
                            
                                if ($targetFile) {
                                    message "info: Found executable: $($targetFile.FullName)"
                                    try {
                                        $versionInfo = (Get-Item $targetFile.FullName).VersionInfo
                                        $assemblyVersion = $versionInfo.ProductVersion
                                    } catch {
                                        message "error: Failed to read version info."
                                        exit 1
                                    }
                            
                                    $PORTAL = $env:PORTALNAME.Split(".")[0]
                                    Write-Output "VERSION_CHECK:$assemblyVersion"
                                    Write-Output "CHECKSUM_MARKER:$zipChecksum"
                                    
                                    message "info: Metadata:"
                                    Get-Content beta_app_update.properties
                                } else {
                                    message "error: No .exe file found."
                                    exit 1
                                }
                            ''').trim()
                            def checksumMatch = (output =~ /CHECKSUM_MARKER:(.*)/)
                            def version = (output =~ /VERSION_CHECK:(.*)/)
                            env.CHECKSUM     = checksumMatch ? checksumMatch[0][1].trim() : ""
                            env.ASSEMBLY_VERSION = version ? version[0][1].trim() : ""
                            echo "${env.CHECKSUM}"
                            echo "${env.ASSEMBLY_VERSION}"
                        }
                        
                        
                    }
                }
            }
        }
        stage('Run Cart Script'){
            agent{label 'built-in'}
            steps{
                withCredentials([sshUserPrivateKey(credentialsId: 'sshhub_key', keyFileVariable: 'SSHHUB_KEY', usernameVariable: 'SSHHUB_USER'), sshUserPrivateKey(credentialsId: 'ansible_key', keyFileVariable: 'ANSIBLE_KEY', usernameVariable: 'ANSIBLE_USER'), string(credentialsId: 'sudopassword', variable: 'SUDOPASS'), string(credentialsId: 'gitpassstring', variable: 'GIT_PASSWORD'), file(credentialsId: 'CLOUD_DB_CREDENTIALS', variable: 'SHARED_CREDENTIALS_FILE')]) {
                    
                    script {
                        
                        sh '''
                        #!/bin/bash
                        set +x
                        set +e
                        message() {
                            echo "\$(date +'%Y-%m-%d %H:%M:%S') \$(hostname) \$1"
                        }
                        export PYTHONWARNINGS=ignore::UserWarning
                        export technician=\$BUILD_USER_EMAIL
                        export REMARKS="\$REMARKS 
                        executed script update_uem_apps_for_windows.py"
                        if [ \"\$PORTALNAME\" = 'Null' ]; then
                            message "error: select portalname from dropdown"
                            exit 1
                        fi
                        message "remarks: \$REMARKS"
                        message "requester: \$REQUESTER"
                        message "info: executing script update_uem_apps_for_windows.py in portal \$PORTALNAME"
                        
                        PORTAL="$(echo "\$PORTALNAME" | cut -d'.' -f1)"
                        DOWNLOAD_URL="https://downloads.hexnode.com/windows-agent/beta/${PORTAL}/HexnodeAuthenticator.zip"
                        cd \${JENKINS_WORKDIR}/repos/cart-scripts
                        message "info: pulling latest cart scripts from gitlab"
                        git pull "https://devops-team:\${GIT_PASSWORD}@gitlab.mitsogo.com/cart/cart-scripts.git"
                        SCRIPTNAME="/var/lib/jenkins/repos/cart-scripts/common/beta_release/update_uem_apps_for_windows.py"
                        BINARY="/usr/bin/python"
                        if [ "$BETA_ENABLED" = "true" ]; then
                            ARGUMENTS="'--app_name ${APP_NAME} --download_url ${DOWNLOAD_URL} --version ${ASSEMBLY_VERSION} --checksum ${CHECKSUM} --beta_enabled'"
                            echo \${ARGUMENTS}
                        else
                            ARGUMENTS="'--app_name ${APP_NAME} --download_url ${DOWNLOAD_URL} --version ${ASSEMBLY_VERSION} --checksum ${CHECKSUM}'"
                            echo \${ARGUMENTS}
                        fi
                        cd \${JENKINS_WORKDIR}/jenkins/playbooks/runscript/
                        python3 $JENKINS_WORKDIR/jenkins/scripts/get_lightsail_ip.py --portal_names "${PORTALNAME}" -file ${WORKSPACE}/inventory_${BUILD_ID}.ini
                        cat ${WORKSPACE}/inventory_${BUILD_ID}.ini
                        if [ -e "${WORKSPACE}/inventory_${BUILD_ID}.ini" ];then
                                ansible-playbook runscript_v2.yml -i ${WORKSPACE}/inventory_${BUILD_ID}.ini \
                                     -e "script=\${SCRIPTNAME}" \
                                     -e "argument=\${ARGUMENTS}" \
                                     -e "binary=\${BINARY}" \
                                     -e "docfile=edithistory" \
                                     --private-key=\$ANSIBLE_KEY \
                                     --user=\$ANSIBLE_USER \
                                     --extra-vars "ansible_sudo_pass=\$SUDOPASS" \
                                     --ssh-extra-args="-p \${PORT:-2160}" \
                                     --ssh-common-args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -i \$SSHHUB_KEY -p 2160 -W %h:%p \$SSHHUB_USER@sshhub.hexnode.com"'
                                exitcode=\$?
                                if [ \$exitcode -eq 0 ]; then
                                    message "info: successfully executed script in \$PORTALNAME"
                                else
                                    message "critical: error while executing script in \$PORTALNAME with exit code \$exitcode"
                                    exit \$exitcode
                                fi
                        else
                                ansible-playbook runscript_v2.yml -i \${PORTALNAME}, \
                                     -e "script=\${SCRIPTNAME}" \
                                     -e "argument=\${ARGUMENTS}" \
                                     -e "binary=\${BINARY}" \
                                     -e "docfile=edithistory" \
                                     --private-key=\$ANSIBLE_KEY \
                                     --user=\$ANSIBLE_USER \
                                     --extra-vars "ansible_sudo_pass=\$SUDOPASS" \
                                     --ssh-extra-args="-p \${PORT:-2160}" \
                                     --ssh-common-args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -i \$SSHHUB_KEY -p 2160 -W %h:%p \$SSHHUB_USER@sshhub.hexnode.com"'
                                exitcode=\$?
                                if [ \$exitcode -eq 0 ]; then
                                    message "info: successfully executed script in \$PORTALNAME"
                                else
                                    message "critical: error while executing script in \$PORTALNAME with exit code \$exitcode"
                                    exit \$exitcode
                                fi
                        fi
                        '''
                    }
                }
            }
        }
    }
    post {
        always {
            /*===================
             Cleaning Workspaces
            ===================*/
            script {
                node('built-in') {
                    echo 'Cleaning workspace...'
                    deleteDir()
                }
                node('windowsbuilder.mitsogo.com') {
                    echo 'Cleaning workspace...'
                    deleteDir()
                }
            }
        }
    }
}
