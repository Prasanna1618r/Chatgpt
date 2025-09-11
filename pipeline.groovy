pipeline {
    agent none
    stages {
        stage('Build App') {
            agent { label 'devopsbuildsrv' }

            steps {

                /*===============================
                 Cleaning workspace before build
                ===============================*/
                // script {
                //     echo "Cleaning workspace..."
                //     deleteDir()
                // }

                script {
                        try {
                            timeout(time: 60, unit: 'MINUTES') { 
                                git branch: params.BRANCH, credentialsId: 'devops_repo_key', url: 'git@gitlab.mitsogo.com:android/chromiumbase.git'
                            }
                        } catch (err) {
                            echo "Git clone timed out: ${err}"
                        }
                }

                withCredentials([string(credentialsId: 'ANDROID_KEY_PASSPHRASE', variable: 'ANDROID_PASSPHRASE'), file(credentialsId: 'JENKINS_AWS_CREDENTIALS', variable: 'AWS_SHARED_CREDENTIALS_FILE'), string(credentialsId: 'jenkins_proxy', variable: 'PROXY'), string(credentialsId: 'gitpassstring', variable: 'GIT_PASSWORD')]) {
                        
                    /*====================================
                     Build App and copy the url in url.txt
                    =======================================*/    
                        
                    sh '''
                        #!/bin/bash
                        message() {
                            echo "$(date +'%Y-%m-%d %H:%M:%S') $(hostname) $1"
                        }

                        #GIT_SSH_COMMAND="ssh -o ConnectTimeout=60" git clone --depth 1 --branch $BRANCH git@gitlab.mitsogo.com:android/chromiumbase.git
                        GIT_COMMIT_SHA=$(git rev-parse --short HEAD)
                        S3_URL="s3://testing-hexnode/jenkins/${JOB_NAME}/${BUILD_NUMBER}"
                        echo "$S3_URL"
                        echo "building hexnode kiosk browser with version $VERSION"

                        export PATH=${JENKINS_WORKDIR}/depot_tools:"$PATH"
                        cd ${JENKINS_WORKDIR}

                        version_check=$(grep -i "chromium Version" $WORKSPACE/README.md | grep  -o "[0-9]*"|head -1)
                        if [ "$VERSION" = "$version_check" ];then
                            echo "Provided version is same as in Readme.md file"
                        else
                            echo "ERROR: Provided version doesnot match with the Readme.md file"
                            exit 1
                        fi


                        if [ "$VERSION" = "90" ]; then
                            version_path=chromium_90
                        elif [ "$VERSION" = "103" ]; then
                            version_path=chromium_103
                        elif [ "$VERSION" = "110" ]; then
                            version_path=chromium_110
                        else
                            version_path=chromium_122
                        fi

                        if [ -e $WORKSPACE/configVersion.json ];then
                            arm_override_version_code=$(cat $WORKSPACE/configVersion.json | jq -r ".arm")
                            arm64_override_version_code=$(cat $WORKSPACE/configVersion.json | jq -r ".arm64")
                        fi
                        arm64_override_version_code="56"
                        arm_override_version_code="55"
                        mkdir -p ${WORKSPACE}/$BUILD_TIMESTAMP
                        echo "Please find the attached link" > ${WORKSPACE}/url.txt
                        mkdir -p ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium

                        #message "building arm apk and aab"
                        if [ -e $WORKSPACE/configVersion.json ];then
                            #sed -i "s/android_override_version_code =.*/android_override_version_code = \"$arm_override_version_code\"/g" $WORKSPACE/build/config/android/config.gni
                            sed -i "s/android_override_version_code =.*/android_override_version_code = \\"$override_version_code\\"/g" $WORKSPACE/build/config/android/config.gni
                            cat ${JENKINS_WORKDIR}/$version_path/src/build/config/android/config.gni | grep -E 'android_override_version_code|android_override_version_name'
                        fi


                        cp -r ${WORKSPACE}/* ${JENKINS_WORKDIR}/$version_path/src/
                        #sed -i "s/^target_cpu =.*/target_cpu = \"arm\"/g" ${JENKINS_WORKDIR}/args.gn
                        sed -i "s/^target_cpu =.*/target_cpu = \\"arm\\"/g" ${JENKINS_WORKDIR}/args.gn
                        cd ${JENKINS_WORKDIR}/$version_path/src/
                        message "info: Generating ninja build files."
                        gn gen out/Default


                        cp ${JENKINS_WORKDIR}/args.gn ${JENKINS_WORKDIR}/$version_path/src/out/Default/args.gn 
                        if [ "$VERSION" = "90" ]; then
                            cd ${JENKINS_WORKDIR}/$version_path/src/chrome/android
                            sed -i '/^[^#][^[]*$/d' chrome_java_resources.gni
                            (for f in $(find java/res/*/ -type f); do echo ' "'$f'",'; done; echo ']') >> chrome_java_resources.gni    
                        fi

                        if [ "$VERSION" = "122" ]; then
                            echo "chrome_pgo_phase = 0" >> ${JENKINS_WORKDIR}/$version_path/src/out/Default/args.gn 
                        fi

                        cd ${JENKINS_WORKDIR}/$version_path/src/chrome/android
                        gclient runhooks
                        cd ${JENKINS_WORKDIR}/$version_path/src/

                        #----------Building HexnodeBrowser-APK--------------
                        echo $APK_ACTION | grep "HexnodeBrowser-APK" > /dev/null
                        if [ $? -eq 0 ]; then
                        message "Info:building chromium apk for arm"
                        ninja -C out/Default chrome_public_apk
                        exitcode=$?
                        if [ $exitcode -ne 0 ];then
                            message "critical:failed building apk"
                        exit 1
                        else
                            message "info:successfully build apk"
                        fi

                        cp ${JENKINS_WORKDIR}/$version_path/src/out/Default/apks/ChromePublic.apk ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.apk
                        cp ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.apk ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_32bit.apk
                        aws s3 cp ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/ "${S3_URL}/" --recursive --region eu-central-1 --profile testing-hexnode --no-progress
                        exitcode=$?

                        if [ $exitcode -ne 0 ];then
                            echo "critical:failed copying files to s3"
                            exit 1
                        else
                            echo "info:successfully copied files to s3"
                        fi
                            aws s3 presign "${S3_URL}/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_32bit.apk" --expires-in 604800 --region eu-central-1 --profile testing-hexnode >> $WORKSPACE/url.txt
                        fi


                        #----------Building HexnodeBrowser-AAB--------------
                        echo $APK_ACTION | grep "HexnodeBrowser-AAB" > /dev/null
                        if [ $? -eq 0 ]; then
                            message "Info:building chromium aab for arm"
                            if  [ "$VERSION" = "122" ]; then
                                bundle_name="ChromePublic.aab"
                                ninja -C ${JENKINS_WORKDIR}/$version_path/src/out/Default chrome_public_bundle
                            else 
                                bundle_name="ChromeModernPublic.aab"
                                ninja -C ${JENKINS_WORKDIR}/$version_path/src/out/Default chrome_modern_public_bundle     
                            fi
                            exitcode=$?
                            if [ $exitcode -ne 0 ];then
                                message "critical:failed building aab bundle"
                                exit 1
                            else
                                message "info:successfully build aab bundle"
                            fi  

                            message "info: Signing the bundle chromium.aab - arm"
                            jarsigner -keystore ${JENKINS_WORKDIR}/certificate.jks ${JENKINS_WORKDIR}/$version_path/src/out/Default/apks/${bundle_name} hexnodemdmapp -storepass $ANDROID_PASSPHRASE
                            exitcode_cp=$?
                            if [ $exitcode_cp -ne 0 ];then
                                message "critical:failed to sign aab bundle"
                                exit 1
                            else
                                message "info:successfully signed aab bundle"
                            fi 

                            cp ${JENKINS_WORKDIR}/$version_path/src/out/Default/apks/${bundle_name} ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.aab
                            cp ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.aab ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_32bit.aab
                            aws s3 cp ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/ "${S3_URL}/" --recursive --region eu-central-1 --profile testing-hexnode --no-progress
                            exitcode=$?

                            if [ $exitcode -ne 0 ];then
                                echo "critical:failed copying files to s3"
                                exit 1
                            else
                                echo "info:successfully copied files to s3"
                            fi

                            aws s3 presign "${S3_URL}/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_32bit.aab" --expires-in 604800 --region eu-central-1 --profile testing-hexnode >> $WORKSPACE/url.txt
                        fi


                        message "building arm64 aab and apk"
                        if [ -e $WORKSPACE/configVersion.json ];then
                            #sed -i "s/android_override_version_code =.*/android_override_version_code = \"$arm64_override_version_code\"/g" $WORKSPACE/build/config/android/config.gni
                            sed -i "s/android_override_version_code =.*/android_override_version_code = \\"$arm64_override_version_code\\"/g" $WORKSPACE/build/config/android/config.gni
                            cat $WORKSPACE/build/config/android/config.gni
                        fi

                        cp -r ${WORKSPACE}/* ${JENKINS_WORKDIR}/$version_path/src/
                        #sed -i "s/^target_cpu =.*/target_cpu = \"arm64\"/g" ${JENKINS_WORKDIR}/args.gn
                        sed -i "s/^target_cpu =.*/target_cpu = \\"arm64\\"/g" ${JENKINS_WORKDIR}/args.gn
                        cd ${JENKINS_WORKDIR}/$version_path/src/

                        message "info: Generating ninja build files.."
                        gn gen out/Default
                        cp ${JENKINS_WORKDIR}/args.gn ${JENKINS_WORKDIR}/$version_path/src/out/Default/args.gn 

                        if [ "$VERSION" = "90" ]; then
                            cd ${JENKINS_WORKDIR}/$version_path/src/chrome/android
                            sed -i '/^[^#][^[]*$/d' chrome_java_resources.gni
                            (for f in $(find java/res/*/ -type f); do echo ' "'$f'",'; done; echo ']') >> chrome_java_resources.gni    
                        fi

                        if [ "$VERSION" = "122" ]; then
                            echo "chrome_pgo_phase = 0" >> ${JENKINS_WORKDIR}/$version_path/src/out/Default/args.gn 
                        fi

                        cd ${JENKINS_WORKDIR}/$version_path/src/chrome/android
                        gclient runhooks
                        cd ${JENKINS_WORKDIR}/$version_path/src/


                        #----------Building HexnodeBrowser-ARM64APK--------------
                        # if [[ "$APK_ACTION" =~ *"HexnodeBrowser-ARM64APK"* ]]; then

                        echo $APK_ACTION | grep "HexnodeBrowser-ARM64APK" > /dev/null
                        if [ $? -eq 0 ]; then
                            message "Info:building chromium apk for arm64"
                            ninja -C out/Default chrome_public_apk
                            exitcode=$?
                            if [ $exitcode -ne 0 ];then
                                message "critical:failed building apk"
                                exit 1
                            else
                                message "info:successfully build apk"
                            fi

                            cp ${JENKINS_WORKDIR}/$version_path/src/out/Default/apks/ChromePublic.apk ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.apk
                            cp ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.apk ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_64bit.apk
                            aws s3 cp ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/ "${S3_URL}/" --recursive --region eu-central-1 --profile testing-hexnode --no-progress
                            
                            exitcode=$?
                            if [ $exitcode -ne 0 ];then
                                echo "critical:failed copying files to s3"
                                exit 1
                            else
                                echo "info:successfully copied files to s3"
                            fi
                            aws s3 presign "${S3_URL}/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_64bit.apk" --expires-in 604800 --region eu-central-1 --profile testing-hexnode >> $WORKSPACE/url.txt
                        fi


                        #----------Building HexnodeBrowser-ARM64AAB--------------
                        #if [[ "$APK_ACTION" =~ *"HexnodeBrowser-ARM64AAB"* ]]; then
                        echo $APK_ACTION | grep "HexnodeBrowser-ARM64AAB" > /dev/null
                        if [ $? -eq 0 ]; then
                            message "info:building aab bundle"
                            if  [ "$VERSION" = "122" ]; then
                                bundle_name="ChromePublic.aab"
                                ninja -C ${JENKINS_WORKDIR}/$version_path/src/out/Default chrome_public_bundle
                            else 
                                bundle_name="ChromeModernPublic.aab"
                                ninja -C ${JENKINS_WORKDIR}/$version_path/src/out/Default chrome_modern_public_bundle     
                            fi

                            exitcode=$?
                            if [ $exitcode -ne 0 ];then
                                message "critical:failed building aab bundle"
                                exit 1
                            else
                                message "info:successfully build aab bundle"
                            fi  

                            message "info: Signing the bundle chromium.aab - arm64"
                            jarsigner -keystore ${JENKINS_WORKDIR}/certificate.jks ${JENKINS_WORKDIR}/$version_path/src/out/Default/apks/${bundle_name} hexnodemdmapp -storepass $ANDROID_PASSPHRASE
                            exitcode_cp=$?
                            if [ $exitcode_cp -ne 0 ];then
                                message "critical:failed to sign aab bundle"
                                exit 1
                            else
                                message "info:successfully signed aab bundle"
                            fi 

                            cp ${JENKINS_WORKDIR}/$version_path/src/out/Default/apks/${bundle_name} ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.aab
                            cp ${WORKSPACE}/$BUILD_TIMESTAMP/HexnodeBrowser.aab ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_64bit.aab
                            aws s3 cp ${WORKSPACE}/$BUILD_TIMESTAMP/version/chromium/ "${S3_URL}/" --recursive --region eu-central-1 --profile testing-hexnode --no-progress
                            
                            exitcode=$?
                            if [ $exitcode -ne 0 ];then
                                echo "critical:failed copying files to s3"
                                exit 1
                            else
                                echo "info:successfully copied files to s3"
                            fi

                            aws s3 presign "${S3_URL}/${GIT_COMMIT_SHA}_HexnodeBrowser_${version_path}_64bit.aab" --expires-in 604800 --region eu-central-1 --profile testing-hexnode >> $WORKSPACE/url.txt
                        fi

                        cat $WORKSPACE/url.txt
                        '''  
                        
                }

                /*=======================================
                Triggering mail by sending build pkg urls
                =========================================*/

                script {
                    withBuildUser {
                        def userEmails = "${env.BUILD_USER_EMAIL}"
                        def fileContent = readFile("${WORKSPACE}/url.txt")
                        echo "Triggering mail to ${userEmails}"
                        emailext(
                            from: "Jenkins Server <jenkins@hexnodemdmnotifications.com>",
                            to: userEmails,
                            subject: "Jenkins Build - ${env.JOB_NAME}",
                            body: """
                                <p>Hi Team,</p>
                                <p>ANDROID HEXNODE KIOSK BROWSER AAB APK was built successfully using Jenkins.</p>
                                <ul>
                                    <li>Build Branch- "${env.BRANCH}"</li>
                                    <li>${fileContent}</li>
                                </ul>

                                <p>Regards,<br/>Jenkins Pipeline<br/>
                                <a href="https://jenkins.mitsogo.com/">jenkins.mitsogo.com</a></p>
                            """,
                            mimeType: 'text/html'
                        )
                    }
                }
                

                /*===================================================
                 Send Mail to QA team to test and Approve deployment
                ===================================================*/
                script {
                    def fileContent = readFile("${WORKSPACE}/url.txt")
                    emailext(
                        from: "Jenkins Server <jenkins@hexnodemdmnotifications.com>",
                        to: "QA-Leads@mitsogo.com",
                        subject: "Approve Deployment: ANDROID BUILD HEXNODE KIOSK BROWSER AAB APK",
                        body: """
                            <p>Hi Team,</p>
                            <p>Please check and approve the deployment of ANDROID HEXNODE KIOSK BROWSER AAB APK</p>
                            <ul>
                                <li>Branch Name  - ${params.BRANCH}</li>
                                <li>${fileContent}</li>
                                <li>Jenkins Job  -  <a href='${env.JOB_URL}'>${env.JOB_NAME}</a></li>
                                <li><b>Approve the deployment</b> <a href='${env.JOB_URL}${env.BUILD_ID}/console'> Here</a></li>
                            </ul><br/>
                            <p>Regards,<br/>Jenkins Pipeline<br/>
                            <a href="https://jenkins.mitsogo.com/">jenkins.mitsogo.com</a></p>
                        """,
                        mimeType: 'text/html'
                    )
                }
            }
        }

        stage('Approve Deployment'){
            agent none
            steps {

                /*===============================
                 Prompting Approval from QA team 
                ===============================*/
                input(
                    id: 'qa-approval',
                    message: "QA Approve deployment for branch '${params.BRANCH}'?",
                    ok: "Approve",
                    cancel: 'Cancel',
                    submitter: 'jibin@mitsogo.com'
                )


                /*===================================
                 Prompting Approval from DevOps team 
                ===================================*/
                input(
                    id: 'devops-approval',
                    message: "DevOps Approve deployment for branch '${params.BRANCH}'?",
                    ok: "Approve",
                    cancel: 'Cancel',
                    submitter: 'alfin.antony@mitsogo.com,vivin@mitsogo.com'
                )
            }
        }

        stage('Deploy'){
            agent{ label 'built-in'}
            steps{
                echo "deploy steps"

                /*================
                 Deploy app in s3 
                =================*/
                withCredentials([file(credentialsId: 'JENKINS_AWS_CREDENTIALS', variable: 'AWS_SHARED_CREDENTIALS_FILE'),string(credentialsId: 'jenkins_proxy', variable: 'PROXY')]) {
                sh '''#!/bin/bash
                    rm -rf $WORKSPACE/version
                    mkdir -p $WORKSPACE/version/chromium $WORKSPACE/version/chromium
                    message() {
                        echo "$(date +\'%Y-%m-%d %H:%M:%S\') $(hostname) $1"
                    }

                    export https_proxy=${PROXY}
                    BUILDJOB_ID=$BUILD_NUMBER
                    BUILD_S3_URL="s3://testing-hexnode/jenkins/$JOB_NAME/$BUILDJOB_ID"
                    DEPLOY_S3_URL="s3://downloads.hexnode.com/"
                    DEPLOY_S3_URL="s3://downloads.hexnode.com/browser-android-8"

                    invalidation_apps=()
                    echo "urls for the deploy:" > $WORKSPACE/url.txt

                    #----------Deploying HexnodeBrowser-APK--------------
                    if [[ $APK_ACTION == *"HexnodeBrowser-APK"* ]]; then
                        message "info: deploying HexnodeBrowser_32bit.apk from s3"
                        file=""
                        file=$(aws s3 ls "${BUILD_S3_URL}/" --profile testing-hexnode --region eu-central-1 | grep -E _HexnodeBrowser_chromium_.*32bit.apk|awk '{print $NF}')
                        if [[ -z "$file" ]]; then
                            message "error: HexnodeBrowser_32bit.apk not found in S3"
                            exit 1
                        fi

                        message "info:Using $file"
                        aws s3 cp "${BUILD_S3_URL}/${file}" "$WORKSPACE/version/chromium/${file}" --profile testing-hexnode --region eu-central-1 --no-progress 
                        if [ $? -ne 0 ] || ! [ -f "$WORKSPACE/version/chromium/${file}" ]; then
                            message "critical: downloading "{$BUILD_S3_URL}/${file}" failed"
                            exit 1
                        fi    
                            
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-32bit.apk" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 && \\
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-32bit.apk.checksum" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 
                        if [ $? -ne 0 ];then
                            message "critacal: error backup failed for hexnodebrowser"
                            exit 1
                        fi

                        sha256sum $WORKSPACE/version/chromium/${file} | awk \'{print $1}\' > $WORKSPACE/version/chromium/${file}.checksum
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/hexnodebrowser-32bit.apk" --profile jenkins --region us-east-1 --acl public-read --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/hexnodebrowser-32bit.apk.checksum" --profile jenkins --region us-east-1 --acl public-read --no-progress && \\
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1  --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1  --no-progress
                        exitcode=$?
                        
                        if [ $exitcode -eq 0 ];then
                            message "info:successfully uploaded files to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-32bit.apk bucket"
                            invalidation_apps+=("/hexnodebrowser-32bit.apk" "/hexnodebrowser-32bit.apk.checksum")   
                            echo "HexnodeBrowser URLs:" >> "$WORKSPACE/url.txt"
                            echo "https://downloads.hexnode.com/browser-android-8/hexnodebrowser-32bit.apk" >> "$WORKSPACE/url.txt"
                            echo "https://downloads.hexnode.com/browser-android-8/hexnodebrowser-32bit.apk.checksum" >> "$WORKSPACE/url.txt"
                        else
                            message "critical: upload file ${file} to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-32bit.apk bucket failed"
                            exit 1
                        fi
                    fi

                    #----------Deploying HexnodeBrowser-ARM64APK--------------
                    if [[ $APK_ACTION == *"HexnodeBrowser-ARM64APK"* ]]; then
                        message "info: deploying HexnodeBrowser_64bit.apk from s3"
                        file=""
                        file=$(aws s3 ls "${BUILD_S3_URL}/" --profile testing-hexnode --region eu-central-1 | grep -E _HexnodeBrowser_chromium_.*64bit.apk| awk '{print $NF}')
                        if [[ -z "$file" ]]; then
                            message "error: HexnodeBrowser_64bit.apk not found in S3"
                            exit 1
                        fi

                        message "info:Using $file"
                        aws s3 cp "${BUILD_S3_URL}/${file}" "$WORKSPACE/version/chromium/${file}" --profile testing-hexnode --region eu-central-1 --no-progress
                        if [ $? -ne 0 ] || ! [ -f "$WORKSPACE/version/chromium/${file}" ]; then
                            message "critical: downloading "{$BUILD_S3_URL}/${file}" failed"
                            exit 1
                        fi    

                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-64bit.apk" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 && \\
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-64bit.apk.checksum" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 
                        if [ $? -ne 0 ];then
                            message "critacal: error backup failed for hexnodebrowser"
                            exit 1 
                        fi

                        sha256sum $WORKSPACE/version/chromium/${file} | awk \'{print $1}\' > $WORKSPACE/version/chromium/${file}.checksum
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/hexnodebrowser-64bit.apk" --profile jenkins --region us-east-1 --acl public-read --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/hexnodebrowser-64bit.apk.checksum" --profile jenkins --region us-east-1 --acl public-read --no-progress && \\
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1  --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1  --no-progress
                        exitcode=$?

                        if [ $exitcode -eq 0 ];then
                            message "info:successfully uploaded files to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.apk bucket"
                            invalidation_apps+=("/hexnodebrowser-64bit.apk" "/hexnodebrowser-64bit.apk.checksum")   
                            echo "HexnodeBrowser URLs:" >> "$WORKSPACE/url.txt"
                            echo "https://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.apk" >> "$WORKSPACE/url.txt"
                            echo "https://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.apk.checksum" >> "$WORKSPACE/url.txt"
                        else
                            message "critical: upload file ${file} to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.apk bucket failed"
                            exit 1
                        fi
                    fi


                    #----------Deploying HexnodeBrowser-AAB--------------
                    if [[ $APK_ACTION == *"HexnodeBrowser-AAB"* ]]; then
                        message "info: downloading HexnodeBrowser_32bit.aab"
                        file=""
                        file=$(aws s3 ls "${BUILD_S3_URL}/" --profile testing-hexnode --region eu-central-1 |  grep -E _HexnodeBrowser_chromium_.*32bit.aab| awk '{print $NF}')
                        if [[ -z "$file" ]]; then
                            message "error: HexnodeBrowser_32bit.aab not found in S3"
                            exit 1
                        fi
                        
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-32bit.aab" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 && \\ 
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-32bit.aab.checksum" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 
                        if [ $? -ne 0 ];then
                        message "critical: error backup failed for HexnodeBrowser_32bit.aab"
                        exit 1
                        fi
                        
                        message "info:Using $file"
                        aws s3 cp "${BUILD_S3_URL}/${file}" "$WORKSPACE/version/chromium/${file}" --profile testing-hexnode --region eu-central-1 --no-progress
                        if [ $? -ne 0 ] || ! [ -f "$WORKSPACE/version/chromium/${file}" ]; then
                            message "critical: downloading "{$BUILD_S3_URL}/${file}" failed"
                            exit 1
                        fi 
                        
                        sha256sum $WORKSPACE/version/chromium/${file} | awk \'{print $1}\' > $WORKSPACE/version/chromium/${file}.checksum
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/hexnodebrowser-32bit.aab" --profile jenkins --region us-east-1  --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/hexnodebrowser-32bit.aab.checksum" --profile jenkins --region us-east-1  --no-progress && \\
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1 --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1 --no-progress
                        exitcode=$?
                        
                        if [ $exitcode -eq 0 ];then
                            message "info:successfully uploaded files to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-32bit.aab bucket"
                            echo "HexnodeBrowser.aab presigned URL: $(aws s3 presign s3://downloads.hexnode.com/HexnodeBrowser_32bit.aab --expires-in 259200 --region us-east-1 --profile jenkins)" >> "$WORKSPACE/url.txt"
                        else
                            message "critical: upload file ${file} to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-32bit.aab bucket failed"
                            exit 1
                        fi
                    fi


                    #----------Deploying HexnodeBrowser-ARM64AAB--------------
                    if [[ $APK_ACTION == *"HexnodeBrowser-ARM64AAB"* ]]; then
                        message "info: downloading HexnodeBrowser_64bit.aab"
                        file=""
                        file=$(aws s3 ls "${BUILD_S3_URL}/" --profile testing-hexnode --region eu-central-1 |  grep -E _HexnodeBrowser_chromium_.*64bit.aab| awk '{print $NF}')
                        if [[ -z "$file" ]]; then
                            message "error: HexnodeBrowser_64bit.aab not found in S3"
                            exit 1
                        fi
                        
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-64bit.aab" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 && \\ 
                        aws s3 cp "$DEPLOY_S3_URL/hexnodebrowser-64bit.aab.checksum" "$DEPLOY_S3_URL/version/backups/$JOB_NAME/${BUILD_TIMESTAMP}/" --profile jenkins --region us-east-1 
                        if [ $? -ne 0 ];then
                        message "critical: error backup failed for hexnodebrowser-64bit.aab"
                        exit 1
                        fi
                        
                        message "info:Using $file"
                        aws s3 cp "${BUILD_S3_URL}/${file}" "$WORKSPACE/version/chromium/${file}" --profile testing-hexnode --region eu-central-1 --no-progress
                        if [ $? -ne 0 ] || ! [ -f "$WORKSPACE/version/chromium/${file}" ]; then
                            message "critical: downloading "{$BUILD_S3_URL}/${file}" failed"
                            exit 1
                        fi 
                        
                        sha256sum $WORKSPACE/version/chromium/${file} | awk \'{print $1}\' > $WORKSPACE/version/chromium/${file}.checksum
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/hexnodebrowser-64bit.aab" --profile jenkins --region us-east-1  --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/hexnodebrowser-64bit.aab.checksum" --profile jenkins --region us-east-1  --no-progress && \\
                        aws s3 cp "$WORKSPACE/version/chromium/${file}" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1 --no-progress && aws s3 cp "$WORKSPACE/version/chromium/${file}.checksum" "$DEPLOY_S3_URL/version/chromium/" --profile jenkins --region us-east-1 --no-progress
                        
                        exitcode=$?
                        if [ $exitcode -eq 0 ];then
                        message "info:successfully uploaded files to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.aab bucket"
                        echo "hexnodebrowser-64bit.aab presigned URL: $(aws s3 presign s3://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.aab --expires-in 259200 --region us-east-1 --profile jenkins)" >> "$WORKSPACE/url.txt"
                        else
                        message "critical: upload file ${file} to s3 https://downloads.hexnode.com/browser-android-8/hexnodebrowser-64bit.aab bucket failed"
                        exit 1
                        fi
                    fi

                    message "info:cloudfront invalidating $invalidation_apps"
                    aws cloudfront create-invalidation --distribution-id EPZX478IV0G2D --paths "${invalidation_apps[@]}" --profile jenkins
                    if [ $? -eq 0 ];then
                        message "info:successfully invalidated app $invalidation_apps"
                    else
                        message "critical: error invalidating app $invalidation_apps"
                        exit 3
                    fi

                    export https_proxy=${PROXY}
                    cat $WORKSPACE/url.txt
                    
                    '''
                }

            }
        }
    }
    post {
        success {

            /*========================
             Sending mail for success
            ========================*/
            script {
                    withBuildUser {
                        def userEmails = "${env.BUILD_USER_EMAIL},cart-team@mitsogo.com,devops-audits@mitsogo.com"
                        def fileContent = readFile("${WORKSPACE}/url.txt")
                        echo "Triggering mail to ${userEmails}"
                        emailext(
                            from: "Jenkins Server <jenkins@hexnodemdmnotifications.com>",
                            to: userEmails,
                            subject: "Jenkins Deployment - ${env.JOB_NAME}",
                            body: """
                                <p>Hi Team,</p>
                                <p>Android Hexnode Kiosk Browser was deployed successfully using Jenkins.</p>
                                <p>Build Branch- "${env.BRANCH}"</p>
                                <p>${fileContent}</p>

                                <p>Regards,</p>
                                <p>Jenkins Server</p>
                                <p>jenkins.mitsogo.com</p>
                            """,
                            mimeType: 'text/html'
                        )
                }
            }
        }


        failure {
            
            /*========================
             Sending mail for failure
            ========================*/
            script {
                emailext (
                    from: "Jenkins Server <jenkins@hexnodemdmnotifications.com>",
                    to: "devops@mitsogo.com",
                    subject: "Deployment Failed: ANDROID HEXNODE KIOSK BROWSER AAB APK",
                    body: """
                        <p>Hi Team,</p>
                        <p>The Deployment <b>${env.JOB_NAME} #${env.BUILD_NUMBER}</b> has failed</span>.</p>
                        <p>Branch - ${params.BRANCH}</p>
                        <p>Please check the logs <a href='${env.BUILD_URL}'>here</a>.</p><br/>
                        <p>Regards,<br/>Jenkins Pipeline<br/>
                        <a href='https://jenkins.mitsogo.com'>jenkins.mitsogo.com</a></p>
                    """,
                    mimeType: 'text/html'
                )
            }
        }

        always {

            /*=========================================
             Sending mail for all run to devops audits
            =========================================*/
            script {
                emailext (
                    from: "Jenkins Server <jenkins@hexnodemdmnotifications.com>",
                    to: "devops-audits@mitsogo.com",
                    subject: "Deployment Status: ANDROID HEXNODE KIOSK BROWSER AAB APK",
                    body: """
                        <p>Hi Team,</p>
                        <p>The build <b>${env.JOB_NAME} #${env.BUILD_NUMBER}</b> has executed</p>
                        <p>Branch - ${params.BRANCH}</p>
                        <p>Job Status - ${currentBuild.currentResult}</p>
                        <p>Please check the logs <a href='${env.BUILD_URL}'>here</a>.</p><br/>
                        <p>Regards,<br/>Jenkins Pipeline<br/>
                        <a href='https://jenkins.mitsogo.com'>jenkins.mitsogo.com</a></p>
                    """,
                    mimeType: 'text/html'
                )
            }


            /*===================
             Cleaning Workspaces
            ===================*/
            // script {
            //     node('devopsbuildsrv') {
            //         echo 'Cleaning workspace...'
            //         deleteDir()
            //     }
            // }
        }
    }
}

