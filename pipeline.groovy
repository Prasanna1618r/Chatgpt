pipeline {
    agent none
    
    environment {
        BUILD_TIMESTAMP = "${new Date().format('yyyyMMddHHmmss')}"
    }

    stages {
        
        stage('Build') {
            when {
                expression { return params.BRANCH?.trim() }
            }
            agent {label 'windowsbuilder.mitsogo.com'}
            steps {
                /*===============================
                 Cleaning workspace before build
                ===============================*/
                script {
                    echo "Cleaning workspace..."
                    deleteDir()
                }
                /*=====================
                 Building Updater App
                =======================*/
                withCredentials([string(credentialsId: 'gitpassstring', variable: 'GIT_PASSWORD'), file(credentialsId: 'JENKINS_AWS_CREDENTIALS', variable: 'AWS_SHARED_CREDENTIALS_FILE')]) {
                    bat '''@echo off
                        set PATH=C:\\Hexnode-Builder\\python-env\\Scripts\\;C:\\Hexnode-Builder\\bin;C:\\Hexnode-Builder\\signtool;C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin;C:\\Program Files\\7-zip\\;%PATH%
                        setlocal enabledelayedexpansion
                        
                        
                        set tempdir=%BUILD_TIMESTAMP%
                        set S3_BASE=s3://testing-hexnode/jenkins/%JOB_NAME%/%BUILD_ID%
                        
                        
                        
                        call :message "info: creating temporary directory %tempdir%
                        mkdir %tempdir% && cd %tempdir%
                        call :message "info: working directory is %cd%"
                        
                        
                        
                        git.exe clone --branch %BRANCH% https://devops-team:%GIT_PASSWORD%@gitlab.mitsogo.com/windowsapplication/windowsupdater.git
                        if %ERRORLEVEL% NEQ 0 ( 
                           call :message "error: while cloning the repo"
                           call :cleanup
                           exit 2
                        )
                        cd windowsupdater
                        
                        
                        call :message "info: branch name"
                        git.exe branch
                        call :message "info: commit info"
                        git.exe log -1
                        if "%COMMIT_SHA%"=="" (
                            call :message "info: commit id is not provided"
                        )else (
                            call :message "info: updating to commit %COMMIT_SHA%"
                            git.exe reset --hard %COMMIT_SHA%
                        )
                        
                        
                        call :message "info: current branch name"
                        git.exe branch
                        call :message "info: commit info"
                        git.exe log -1
                        for /f %%G in (\'git.exe rev-parse --short HEAD\') do set "GIT_COMMIT_SHA=%%G"
                        
                        
                        if not "%ASSEMBLY_VERSION%"=="" (
                            powershell -Command "(Get-Content -Path \'Properties\\AssemblyInfo.cs\') -replace \'\\[assembly: AssemblyVersion\\(".*"\\)\\]\', \'[assembly: AssemblyVersion(\\"%ASSEMBLY_VERSION%\\")]\' -replace \'\\[assembly: AssemblyFileVersion\\(".*"\\)\\]\', \'[assembly: AssemblyFileVersion(\\"%ASSEMBLY_VERSION%\\")]\' | Set-Content -Path \'Properties\\AssemblyInfo.cs\'"
                        )
                        set "FILE_PATH=Properties\\AssemblyInfo.cs"
                        for /f "tokens=*" %%i in (\'findstr /r "^\\[assembly:.*AssemblyVersion(" %FILE_PATH%\') do (
                            set "line=%%i"
                            set "line=!line:[=!"
                            set "line=!line:]=!"
                            set "line=!line:assembly=!"
                            set "line=!line:AssemblyVersion=!"
                            set "line=!line::=!"
                            set "line=!line:(=!"
                            set "line=!line:)=!"
                            set "line=!line:"=!"
                            set "line=!line: =!"
                            set "line=!line:Version=!"
                            set "ASSEMBLY_VERSION=!line!"
                        )
                        call :message "info: ASSEMBLY_VERSION is %ASSEMBLY_VERSION%"
                        
                        
                        call :message "info: running => nuget.exe restore HexnodeUpdater.sln"
                        nuget.exe restore HexnodeUpdater.sln
                        if %ERRORLEVEL% NEQ 0 ( 
                           echo "error:failed install packages defined in HexnodeUpdater.sln"
                           exit 2
                        )
                        
                        call :message "info: running => MSBuild.exe HexnodeUpdater.csproj"
                        MSBuild.exe HexnodeUpdater.csproj
                        if %ERRORLEVEL% NEQ 0 ( 
                           echo "error:failed to build HexnodeUpdater.csproj"
                           exit 1
                        )
                        
                        copy bin\\Debug\\bin\\HexnodeUpdater.exe bin\\Debug\\
                        rmdir /s /Q bin\\Debug\\bin\\
                        cd bin\\Debug\\
                        7z.exe a -tzip ..\\..\\..\\windowsupdater.zip ./*
                        
                        call :message "info: zip archive is available in location %tempdir%/windowsupdater.zip"
                        
                        for /f "skip=1 tokens=1" %%i in (\'certutil -hashfile ..\\..\\..\\windowsupdater.zip SHA256\') do (
                            set "CHECKSUM=%%i"
                            goto :done
                        )
                        :done
                        
                        for /f "delims=. tokens=1" %%A in ("%PORTALNAME%") do (
                            set "PORTAL=%%A"
                        )
                        
                        echo PORTALNAME=%PORTALNAME%> %WORKSPACE%\\beta_app_update.properties
                        echo APP_NAME=updater>> %WORKSPACE%\\beta_app_update.properties
                        echo VERSION=%ASSEMBLY_VERSION%>> %WORKSPACE%\\beta_app_update.properties
                        echo DOWNLOAD_URL=https://downloads.hexnode.com/windows-agent/beta/%PORTAL%/HexnodeUpdater.zip>> %WORKSPACE%\\beta_app_update.properties
                        echo CHECKSUM=%CHECKSUM%>> %WORKSPACE%\\beta_app_update.properties
                        type %WORKSPACE%\\beta_app_update.properties
                        
                        call :message "info: uploading zip file to s3"
                        call aws s3 cp "..\\..\\..\\windowsupdater.zip" ^
                                       "s3://downloads.hexnode.com/windows-agent/beta/%PORTAL%/HexnodeUpdater.zip" ^
                                                     --profile jenkins --no-progress --acl public-read
                        if %ERRORLEVEL% NEQ 0 ( 
                           call :message "error: while uploading HexnodeUpdater.zip file to s3"
                           call :cleanup
                           exit 1
                        )
                        
                        echo "info: zip file is available in s3 location: " 
                        echo https://downloads.hexnode.com/windows-agent/beta/%PORTAL%/HexnodeUpdater.zip
                        
                        call :message "info: signing HexnodeUpdater.zip."
                        echo S3_URL="s3://downloads.hexnode.com/windows-agent/beta/%PORTAL%/HexnodeUpdater.zip" > %WORKSPACE%\\signing_parameters.properties
                        echo FILE_NAME="HexnodeUpdater.exe" >> %WORKSPACE%\\signing_parameters.properties
                        echo IS_S3_URL_PUBLIC=True >> %WORKSPACE%\\signing_parameters.properties
                        type %WORKSPACE%\\signing_parameters.properties
                        
                        endlocal
                        exit /b
                        REM ########### Functions Declaring Section ##############
                        
                        :message
                        echo.
                        for /f "tokens=2 delims==" %%a in (\'wmic os get localdatetime /value\') do set datetime=%%a
                        set timestamp=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2% %datetime:~8,2%:%datetime:~10,2%:%datetime:~12,2%
                        echo [%timestamp% %NODE_NAME%] %1
                        exit /b
                        
                        
                        :cleanup
                        cd %WORKSPACE%
                        echo "info: working directory is %cd%"
                        echo "info: clearing temporary directory %tempdir%"
                        rmdir /s /Q "%tempdir%"
                        exit /b'''
                    stash includes: 'beta_app_update.properties', name: 'betaprops'
                    /*===================
                    Signing Updater App
                    ====================*/
                    script {
                        def paramMap = readProperties file: 'signing_parameters.properties'
                        build job: 'TEST_DEPLOY_WINDOWS_SIGN_APP', parameters: [
                            string(name: 'S3_URL',           value: "${paramMap.S3_URL}"),
                            string(name: 'FILE_NAME',        value: "${paramMap.FILE_NAME}"),
                            string(name: 'IS_S3_URL_PUBLIC', value: "${paramMap.IS_S3_URL_PUBLIC}")
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
                script {
                    echo "Cleaning workspace..."
                    deleteDir()
                }
                
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

                        powershell '''
                            function message($msg) {
                                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                $nodeName = $env:NODE_NAME
                                Write-Host "[$timestamp $nodeName] $msg"
                            }
                        
                            message "info: Starting extraction and checksum calculation..."
                        
                            try {
                                Expand-Archive -Path HexnodeUpdater.zip -DestinationPath extracted -Force
                            } catch {
                                message "error: Failed to extract ZIP file."
                                exit 1
                            }
                        
                            try {
                                $zipChecksum = (Get-FileHash -Path "HexnodeUpdater.zip" -Algorithm SHA256).Hash
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
                                "APP_NAME=updater" | Out-File -FilePath beta_app_update.properties -Encoding ASCII
                                "VERSION=$assemblyVersion" | Out-File -Append -FilePath beta_app_update.properties -Encoding ASCII
                                "DOWNLOAD_URL=https://downloads.hexnode.com/windows-agent/beta/$PORTAL/HexnodeUpdater.zip" | Out-File -Append -FilePath beta_app_update.properties -Encoding ASCII
                                "CHECKSUM=$zipChecksum" | Out-File -Append -FilePath beta_app_update.properties -Encoding ASCII
                        
                                message "info: Metadata:"
                                Get-Content beta_app_update.properties
                            } else {
                                message "error: No .exe file found."
                                exit 1
                            }
                        '''
                        stash includes: 'beta_app_update.properties', name: 'betaprops'
                    }
                }
            }
        }
        stage('Run Cart Script'){
            agent{label 'built-in'}
            steps{
                withCredentials([sshUserPrivateKey(credentialsId: 'sshhub_key', keyFileVariable: 'SSHHUB_KEY', usernameVariable: 'SSHHUB_USER'), sshUserPrivateKey(credentialsId: 'ansible_key', keyFileVariable: 'ANSIBLE_KEY', usernameVariable: 'ANSIBLE_USER'), string(credentialsId: 'sudopassword', variable: 'SUDOPASS'), string(credentialsId: 'gitpassstring', variable: 'GIT_PASSWORD'), file(credentialsId: 'CLOUD_DB_CREDENTIALS', variable: 'SHARED_CREDENTIALS_FILE')]) {
                    
                    script {
                        echo "Cleaning workspace..."
                        deleteDir()
                    }
                    unstash 'betaprops'
                    script {
                        def paramMap = readProperties file: 'beta_app_update.properties'
                        def APP_NAME = paramMap.APP_NAME
                        def VERSION = paramMap.VERSION
                        def DOWNLOAD_URL = paramMap.DOWNLOAD_URL
                        def CHECKSUM = paramMap.CHECKSUM
                        sh """
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
                        

                        cd \${JENKINS_WORKDIR}/repos/cart-scripts
                        message "info: pulling latest cart scripts from gitlab"
                        git pull "https://devops-team:\${GIT_PASSWORD}@gitlab.mitsogo.com/cart/cart-scripts.git"
                        SCRIPTNAME="/var/lib/jenkins/repos/cart-scripts/common/beta_release/update_uem_apps_for_windows.py"
                        BINARY="/usr/bin/python"
                        if [ "$BETA_ENABLED" = "true" ]; then
                            ARGUMENTS="'--app_name ${APP_NAME} --download_url ${DOWNLOAD_URL} --version ${VERSION} --checksum ${CHECKSUM} --beta_enabled'"
                            echo \${ARGUMENTS}
                        else
                            ARGUMENTS="'--app_name ${APP_NAME} --download_url ${DOWNLOAD_URL} --version ${VERSION} --checksum ${CHECKSUM}'"
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
                        """
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
