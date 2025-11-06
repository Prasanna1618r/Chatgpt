#!/bin/sh


projectdir="/var/www/html/mobarmour"
workdir="/opt/mitsogo"
logdir="/var/log/hexnode"

message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') $1"

}

if [ -f "${workdir}/runremotequery.conf" ];then
    . "${workdir}/runremotequery.conf"
fi

if [ -z "$SettingsFile" ];then
    message "critical:SettingsFile variable missing"
    exit 1
fi

if [ ! -f "$SettingsFile" ] && [ "$SettingsFile" != "/dev/null" ];then
    message "critical:settingsfile missing"
    exit 2
fi

AccessFile="${logdir}/access.log"
ErrorFile="${logdir}/error.log"
HexnodemdmFile="${logdir}/hexnodemdm.log"

ApacheProductionConf="/etc/httpd/conf.d/production.conf"
multiserverfile="/opt/mitsogo/multiserver"

AccessLogPointer_403="/tmp/AccessLogPointer_403"
AccessLogPointer_500="/tmp/AccessLogPointer_500"
AccessLogPointer_503="/tmp/AccessLogPointer_503"
celeryexeclimitPointer="/tmp/celeryexeclimitPointer"
toptimelimiter="/tmp/responsetimePointer"

celerysuccessmaxtime=20

dbhost=$(grep "'HOST':"  $SettingsFile|awk -F ':' '{print $2}'|sed "s/[, ']//g")
dbport=$(grep "'PORT':"  $SettingsFile|awk -F ':' '{print $2}'|sed "s/[, ']//g")
dbuser=$(grep "'USER':"  $SettingsFile|awk -F ':' '{print $2}'|sed "s/[, ']//g")
dbname=$(grep "'NAME':"  $SettingsFile|awk -F ':' '{print $2}'|sed "s/[, ']//g")
dbpasswd=$(grep "'PASSWORD':"  $SettingsFile|awk -F ':' '{print $2}'|sed "s/[, ']//g")

dbhost=${dbhost:-$DBHOST}
dbport=${dbport:-$DBPORT}
dbuser=${dbuser:-$DBUSER}
dbname=${dbname:-$DBNAME}
dbpasswd=${dbpasswd:-$DBPASSWD}

rundbquery(){

    local output
    output=$(PAGER= PGPASSWORD=$dbpasswd PGCONNECT_TIMEOUT=5 psql -h $dbhost -p $dbport -U $dbuser -d $dbname -t -c "$1")
    echo "$output"

}

subject="$1"

case $subject in
    QueryCount)
        rundbquery "select count(*) from pg_stat_activity where datname='$dbname'"
        ;;

    DBcrash)
        netstat -ant|awk '{print $5}'|grep -Ec ":$dbport"
        ;;

    dbconnectioncount)
        netstat -ant|grep 'ESTABLISHED'|awk '{print $5}'|grep -Ec ":$dbport"
        ;;

    DbSize)
        rundbquery "SELECT pg_size_pretty( pg_database_size('$dbname') )"
        ;;
    
    CeleryTaskQueue)
        rundbquery "select COALESCE(count(*), 0) from djkombu_message where queue_id in (select id from djkombu_queue where name = 'celery') and visible='True';"
        ;;

    CeleryTaskQueueLowPriority)
        rundbquery "select count(*) from djkombu_message where queue_id != (select id from djkombu_queue where name = 'celery') and visible='True';"
        ;;
    
    CeleryHighTaskQueue)
           rundbquery "select COALESCE(count(*), 0) from djkombu_message where queue_id in (select id from djkombu_queue where name = 'high') and visible='True';"
        ;;
    
    CeleryLowTaskQueue)
           rundbquery "select COALESCE(count(*), 0) from djkombu_message where queue_id in (select id from djkombu_queue where name = 'low') and visible='True';"
        ;;
    
    CelerySpecialTaskQueue)
        rundbquery "select COALESCE(count(*), 0) from djkombu_message where queue_id in (select id from djkombu_queue where name not in ('high','low','celery') and name not like '%celery.pidbox') and visible='True';"
        ;;

    CommandMapper)
        rundbquery "select count(*) from base_commanddevicemapper inner join base_enrolleddevice on base_commanddevicemapper.device_id=base_enrolleddevice.id where base_commanddevicemapper.command_status in (1,2) and base_enrolleddevice.enrollment_status in (1,2);"
        ;;

    TotalDeviceCount)
        rundbquery "select value from base_globalsettings where key='zabbix_devicelimit';"
        ;;

    ActiveDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5);"
        ;;

    androidDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=3;"
        ;;

    windowsDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=2;"
        ;;

    iosDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=1;"
        ;;

    macDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=4;"
        ;;

    tvosDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=5;"
        ;;
    
    linuxDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=6;"
        ;;

    visionDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=7;"
        ;;
    
    chromeDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform=8;"
        ;;

    fireDeviceCount)
        rundbquery "select count(*) from base_device where device_id_id in (select id from base_enrolleddevice where enrollment_status in (1,5)) and lower(product_name) = 'amazon' and lower(manufacture) = 'amazon';"
        ;;

    androidtvDeviceCount)
        rundbquery "select count(*) from base_device where device_id_id in (select id from base_enrolleddevice where enrollment_status in (1, 5) and platform = 3) and device_type in (7, 8);"
        ;;

    otherDeviceCount)
        rundbquery "select count(*) from base_enrolleddevice where enrollment_status in (1,5) and platform not in (1,2,3,4,5,6,7,8);"
        ;;

    UpdationStatus)
        [ $(ls /tmp|grep -Ec '*.lock$') -gt 0 ] && echo "1" || echo "0"
        ;;

    DBHealth)
        [[ $(rundbquery "SELECT 200") == '200' ]] && echo 1 || echo 0
        ;;

    ADHealth)
        if [[ -f /etc/init.d/agentserver ]]; then
            ps -u apache -o cmd=|grep -Ec '[a]dserver_start'
        else
            echo 1
        fi  
        ;;

    celery)
        if [[ -f /etc/init.d/celery ]]; then
            ps -u apache -o cmd=|grep -Ec '[c]elery-w1.pid'
        else
            echo 1
        fi
        ;;

    celerybeat)
        if [[ -f /etc/init.d/celerybeat ]]; then
            ps -u apache -o cmd=|grep -Ec '[c]elerybeat.pid'
        else
            echo 1
        fi  
        ;;

    celeryhigh)
        if [[ -f /etc/init.d/celeryhigh ]]; then
            ps -u apache -o cmd=|grep -Ec '[c]eleryhigh-w1.pid'
        else
            echo 1
        fi
        ;;

    celerylow)
        if [[ -f /etc/init.d/celerylow ]]; then
            ps -u apache -o cmd=|grep -Ec '[c]elerylow-w1.pid'
        else
            echo 1
        fi
        ;;

    500)
        if [[ -f $AccessLogPointer_500 ]];then
            accesslog_500=$(cat $AccessLogPointer_500)
            if [[ $accesslog_500 -le 0 ]]; then
                wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_500
                tail -100 $AccessFile|awk '{print $9}'|grep -c '500'
            else
                tail -n+$accesslog_500 $AccessFile|awk '{print $9}'|grep -c '500'
                wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_500
            fi
        else
            wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_500
            tail -100 $AccessFile|awk '{print $9}'|grep -c '500'
        fi
        ;;

    503)
        if [[ -f $AccessLogPointer_503 ]];then
            accesslog_503=$(cat $AccessLogPointer_503)
            if [[ $5accesslog_503 -le 0 ]]; then
                wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_503
                tail -100 $AccessFile|awk '{print $9}'|grep -c '503\|504\|502'
            else
                tail -n+$accesslog_503 $AccessFile|awk  '{print $9}'|grep -c '503\|504\|502'
                wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_503
            fi
        else
            wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_503
            tail -100 $AccessFile|awk '{print $9}'|grep -c '503\|504\|502'
        fi
        ;;

    403)
        if [[ -f $AccessLogPointer_403 ]];then
            accesslog_403=$(cat $AccessLogPointer_403)
            if [[ $accesslog_403 -le 0 ]]; then
                wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_403
                tail -100 $AccessFile|awk '{print $9}'|grep -c 403
            else
                tail -n+$accesslog_403 $AccessFile|awk  '{print $9}'|grep -c 403
                wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_403
            fi
        else
            wc -l $AccessFile|awk '{print $1}' > $AccessLogPointer_403
            tail -100 $AccessFile|awk '{print $9}'|grep -c 403
        fi
        ;;

    404)
        tail -100 $AccessFile|awk '{print $9}'|grep -c 404
        ;;

    currentqueries)
        PGCONNECT_TIMEOUT=3 PGPASSWORD=$dbpasswd psql -h $dbhost -p $dbport -U $dbuser -d $dbname -t -c "select pid,client_port,client_addr,query from pg_stat_activity where datname='$dbname' order by client_addr"
        ;;

    ApiHits)
        apistatus=$(grep '^[ ]*Define disableApi' "$ApacheProductionConf")
        timebase=$(date +%d/%b/%Y)
        if [[ !  -z  '$apistatus' ]]; then
            echo "0"
        else
            grep -E "$timebase" $AccessFile|grep '/api/v1/'|grep -Ev "DevopsMon|Zabbix|StatusCake|365andup"|grep -c 'HTTP/1.1" 200'
        fi
        ;;

    accesslog)
        tail -500 $AccessFile
        ;;

    hexnodemdmlog)
        tail -500 $HexnodemdmFile
        ;;

    errorlog)
        tail -500 $ErrorFile
        ;;

    PendingCeleryTasks)
        python /opt/mitsogo/listceleryqueue.py |awk -F ',' '{if ( $2 == "True" ) {print $4}}'
        ;;

    ActiveCeleryTasks)
        python /opt/mitsogo/listceleryqueue.py |awk -F ',' '{if ( $2 == "False" ) {print $4}}'
        ;;

    UniqueTasks)
        python /opt/mitsogo/listceleryqueue.py |awk -F ',' '{if ( $2 == "True" ) {print $4}}'|sort|uniq -c
        ;;
    
    UniqueTasksExtended)
        python /opt/mitsogo/listceleryqueue.py > /tmp/queue
        echo "task details"
        awk -F ',' '{if ( $2 == "True" ) {print $4" "$3}}' /tmp/queue|sort|uniq -c|sort -n -r
        echo -e "\nqueue details"
        awk -F ',' '{if ( $2 == "True" ) {print $3}}' /tmp/queue |sort|uniq -c|sort -n -r
        rm -f /tmp/queue
        ;;

    CpuUsage)
        CORECOUNT=$(grep -c ^processor /proc/cpuinfo)
        CPUUSAGE=$(top -bn 1 | awk -v n=$CORECOUNT 'NR > 7 { s += $9 } END { print int(s / n + .5); }')
        echo $CPUUSAGE
        ;;

    CpuDetails)
        echo "cpu details"
        top -cbn 1|awk 'NR>=7 && NR<=17'
        echo -e "\nextended cpu details"
        ps -eo pid,lstart,%cpu,cmd --sort=-%cpu|head -n 10
        ;;

    RamDetails)
        echo "ram details"
        if top -v 2> /dev/null|grep -q "procps-ng" || top -V 2> /dev/null|grep -q "procps-ng" ;then
            top -o %MEM -cbn 1|awk "NR>=7 && NR<=17"
        else
            top -a -cbn 1|awk "NR>=7 && NR<=17"
        fi
        echo -e "\nextended ram details"
        ps -eo pid,lstart,%mem,cmd --sort=-rss|head -n 10
        ;;
    
    SwapDetails)
        echo "swap details"
        ps -eo pmem,pcpu,vsize,pid,cmd --sort=-rss|head -5
        ;;

    Region)
        echo `(grep '^REGION[ ]*=' $SettingsFile|tail -n 1|awk -F '=' '{print $2}'|sed "s/[, '\"]//g")`
        ;;

    CeleryBlockedStatus)
        [ -f /tmp/celery_blocked ] && echo "1" || echo "0"
        ;;

    Portaltype)
        Portaltype=$(rundbquery "select value from base_globalsettings where key='zabbix_portaltype';")
        echo -e "$Portaltype"
        ;;

    DBinfo)
        echo -e "$dbhost"
        ;;

    PortalBasicInfo)
        cd $projectdir

        echo -e "#### Git Info ####"
        branch=$(git rev-parse --abbrev-ref HEAD)
        commit_sha=$(git log -1 --format=%H)
        Build_version=$(grep '^LISTEN_BUILD_NUMBER' $SettingsFile|grep -Po 'HEXNODE_MDM_+[0-9]+_[0-9]+_[0-9]+')
        Devops_Build_Version=$(grep '^DEVOPS_BUILD_NUMBER' $SettingsFile|grep -Po 'HEXNODE_MDM_+[0-9]+_[0-9]+_[0-9]+')
        custommodification=$(git ls-files -m)
        echo -e "Git_Branch=$branch\nCommit_sha=$commit_sha\nBuild_Version=${Build_version:-Unspecified}\nDevops_Version=${Devops_Build_Version:-Unspecified}\nCustom_Modification=${custommodification:-No Changes Found}\n"

        echo -e "#### Apache Conf Info ####"
        apacheconfver=$(grep 'confversion' /etc/httpd/conf/httpd.conf|grep -Eo '[0-9]*')
        apacheprodconf=$(grep -Ev '^#.*|^$' "$ApacheProductionConf")
        if [[ $apacheprodconf != *"Define consolePcount"* ]];then
            consolecount=$(grep "Define consolePcount" /etc/httpd/conf/httpd.conf|awk '{$1=$1};1')
            apacheprodconf="${consolecount}\n$apacheprodconf"
        fi
        echo -e "ApacheConfInfo=$apacheconfver \nApacheProductionConf\n$apacheprodconf\n"

        echo -e "#### Portal Info ####"
        region=$(grep '^REGION[ ]*=' $SettingsFile|tail -n 1|awk -F '=' '{print $2}'|sed "s/[, '\"]//g")
        portaldate=$(rundbquery "select value from base_globalsettings where key='SYSTEM_STRING';")
        activity=$(sh ${projectdir}/checkuseraccess.sh>/dev/null 2>&1;echo $?)
        PortalDeviceLimit=$(rundbquery "select value from base_globalsettings where key='zabbix_devicelimit';")
        Portaltype=$(rundbquery "select value from base_globalsettings where key='zabbix_portaltype';")
        echo "Portal Created Date=$portaldate"
        echo "Region=$region"
        echo "Activity=$activity"
        echo "Portal_Type=$Portaltype"
        echo "Portal_Device_Limit=$PortalDeviceLimit"
        echo ""
        
        echo -e "#### Database Info ####"
        echo -e "dbhost=$dbhost \ndbport=$dbport \ndbuser=$dbuser \ndbname=$dbname"
        echo ""

        echo -e "#### Lock file Info ####"
        if [ $(ls /tmp|grep -Ec '*.lock$') -gt 0 ];then
            ls /tmp/*.lock
        else
            echo "no lock files"
        fi

        echo -e "\n#### Multiserver Info ####"
        if [[ -f $multiserverfile ]];then
            echo "Multiserver"
            cat "$multiserverfile"
        else
            echo "Not multiserver"
        fi

        echo -e "\n#### Celery Services ####"
        if [[ -f /etc/init.d/celeryhigh ]]; then
            echo "celeryhigh"
        fi

        if [[ -f /etc/init.d/celerylow ]]; then
            echo "celerylow"
        fi

        if [[ -f /etc/init.d/celery ]]; then
            echo "celery"
        fi
      ;;

    celeryexectime)
        if [[ -f $celeryexeclimitPointer ]];then
            celeryexeclimit=$(cat $celeryexeclimitPointer)
            if [[ $celeryexeclimit -le 0 ]]; then
                wc -l $HexnodemdmFile|awk '{print $1}' > $celeryexeclimitPointer
                celerytask=$(tail -100 $HexnodemdmFile|grep -w "celery.worker" |grep -Eo "Task .* succeeded in [0-9]+"|awk '{print $2" "$5}'|sort -k2 -n -r|head -1)

                celerytime=$(echo "$celerytask"|awk '{print $2}')
                if [ ${celerytime:-0} -gt $celerysuccessmaxtime ];then
                    echo "$celerytask"
                fi
            else
                celerytask=$(tail -n+$celeryexeclimit $HexnodemdmFile|grep -w "celery.worker" |grep -Eo "Task .* succeeded in [0-9]+"|awk '{print $2" "$5}'|sort -k2 -n -r|head -1)

                celerytime=$(echo "$celerytask"|awk '{print $2}')
                if [ ${celerytime:-0} -gt $celerysuccessmaxtime ];then
                    echo "$celerytask"
                fi
                wc -l $HexnodemdmFile|awk '{print $1}' > $celeryexeclimitPointer
            fi
        else
            wc -l $HexnodemdmFile|awk '{print $1}' > $celeryexeclimitPointer
            celerytask=$(tail -100 $HexnodemdmFile|grep -w "celery.worker" |grep -Eo "Task .* succeeded in [0-9]+"|awk '{print $2" "$5}'|sort -k2 -n -r|head -1)

            celerytime=$(echo "$celerytask"|awk '{print $2}')
            if [ ${celerytime:-0} -gt $celerysuccessmaxtime ];then
                echo "$celerytask"
            fi
        fi
        ;;

    Top_apache_response_time)
        if [[ -f $toptimelimiter ]];then
            timelimit=$(cat $toptimelimiter)
            if [[ $timelimit -le 0 ]]; then
                wc -l $AccessFile|awk {'print $1'} > $toptimelimiter
                tail -100  $AccessFile|awk {'print $NF'} |cut -d '/' -f1 |sort -r|head -1
            else
                tail -n +$timelimit $AccessFile|awk {'print $NF'} |cut -d '/' -f1 |sort -r|head -1
                wc -l $AccessFile|awk '{print $1}' > $toptimelimiter
            fi
        else
            wc -l $AccessFile|awk '{print $1}' > $toptimelimiter
            tail -100  $AccessFile|awk {'print $NF'} |cut -d '/' -f1 |sort -r|head -1
        fi
        ;;
    
    ntpd_status)
        ntpstat > /dev/null 2>&1
        exitcode=$?
        [ "$exitcode" -eq 0 ] && echo 1 || echo 0
        ;;
    
    fail2ban_status)
        ps -e -o comm=|grep -c '[f]ail2ban-server'
        ;;
    
    auditLogStatus)
        pid=$(cat /var/run/mitsogoaudit.pid 2>/dev/null)
        if [ ! -z $pid ] && [ "$(ps -p $pid -o comm=)" = 'sessionnotifier' ];then
           echo 1
        else
           echo 0
        fi
        ;;
    
    *)
        echo "unsupported command"
        ;;

esac
