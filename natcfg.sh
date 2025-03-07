#!/bin/bash

red="\033[31m"
black="\033[0m"

base=/etc/dnat
mkdir $base 2>/dev/null
conf=$base/conf
touch $conf

clear
echo "#############################################################"
echo "# Usage: setup iptables nat rules for domian/ip             #"
echo "# Website:  http://www.arloor.com/                          #"
echo "# Author: ARLOOR <admin@arloor.com>                         #"
echo "# Github: https://github.com/arloor/iptablesUtils           #"
echo "#############################################################"
echo

setupService(){
    cat > /usr/local/bin/dnat.sh <<"AAAA"
#! /bin/bash
[[ "$EUID" -ne '0' ]] && echo "Error:This script must be run as root!" && exit 1;

base=/etc/dnat
mkdir $base 2>/dev/null
conf=$base/conf
firstAfterBoot=1
lastConfig="/iptables_nat.sh"
lastConfigTmp="/iptables_nat.sh_tmp"

####
echo "正在安装依赖...."
yum install -y bind-utils &> /dev/null
apt install -y dnsutils &> /dev/null
echo "Completed：依赖安装完毕"
echo ""
####
turnOnNat(){
    # 开启端口转发
    echo "1. 端口转发开启  【成功】"
    sed -n '/^net.ipv4.ip_forward=1/'p /etc/sysctl.conf | grep -q "net.ipv4.ip_forward=1"
    if [ $? -ne 0 ]; then
        echo -e "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && sysctl -p
    fi

    #开放FORWARD链
    echo "2. 开放iptbales中的FORWARD链  【成功】"
    arr1=(`iptables -L FORWARD -n  --line-number |grep "REJECT"|grep "0.0.0.0/0"|sort -r|awk '{print $1,$2,$5}'|tr " " ":"|tr "\n" " "`)
    for cell in ${arr1[@]}
    do
        arr2=(`echo $cell|tr ":" " "`)
        index=${arr2[0]}
        echo 删除禁止FOWARD的规则$index
        iptables -D FORWARD $index
    done
    iptables --policy FORWARD ACCEPT
}
turnOnNat

testVars(){
    local localport=$1
    local remotehost=$2
    local remoteport=$3
    # 判断端口是否为数字
    local valid=
    echo "$localport"|[ -n "`sed -n '/^[0-9][0-9]*$/p'`" ] && echo $remoteport |[ -n "`sed -n '/^[0-9][0-9]*$/p'`" ]||{
       echo  -e "${red}本地端口和目标端口请输入数字！！${black}";
       return 1;
    }
}

dnat(){
    [ "$#" = "5" ] && {
        local localport=$1
        local interface=$2
        local remote=$3
        local remoteport=$4
        local source_ip=$5

        cat >> $lastConfigTmp <<EOF
iptables -t nat -A PREROUTING -i $interface -p tcp --dport $localport -j DNAT --to-destination $remote:$remoteport
iptables -t nat -A PREROUTING -i $interface -p udp --dport $localport -j DNAT --to-destination $remote:$remoteport
iptables -t nat -A POSTROUTING -p tcp -d $remote --dport $remoteport -j SNAT --to-source $source_ip
iptables -t nat -A POSTROUTING -p udp -d $remote --dport $remoteport -j SNAT --to-source $source_ip
EOF
    }
}

dnatIfNeed(){
    [ "$#" = "5" ] && {
        local needNat=0
        # 如果已经是ip
        if [ "$(echo $3 | grep -E -o '([0-9]{1,3}[\.]){3}[0-9]{1,3}')" != "" ];then
            local remote=$3
        else
            local remote=$(host -t a $3|grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"|head -1)
        fi

        if [ "$remote" = "" ];then
            echo Warn:解析失败
            return 1;
        fi
    }||{
        echo "Error: host命令缺失或传递的参数数量有误"
        return 1;
    }
    echo $remote >$base/${1}IP
    dnat $1 $2 $remote $4 $5
}

echo "3. 开始监听域名解析变化"
echo ""
while true ;
do
## 获取本机地址（这里仅作为默认值，不直接用于SNAT）
localIP=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1 | grep -Ev '(^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.1[6-9]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.2[0-9]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.3[0-1]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$)')
if [ "${localIP}" = "" ]; then
    localIP=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1|head -n 1 )
fi
echo  "本机默认IP [$localIP]"
cat > $lastConfigTmp <<EOF
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
EOF
arr1=(`cat $conf`)
for cell in ${arr1[@]}
do
    arr2=(`echo $cell|tr ":" " "|tr ">" " "`)  # arr2=localport interface remotehost remoteport source_ip
    # 过滤非法的行
    [ "${arr2[4]}" != "" -a "${arr2[5]}" = "" ] && testVars ${arr2[0]} ${arr2[2]} ${arr2[3]} && {
        echo "转发规则： ${arr2[0]} => ${arr2[1]} => ${arr2[2]}:${arr2[3]} (源IP: ${arr2[4]})"
        dnatIfNeed ${arr2[0]} ${arr2[1]} ${arr2[2]} ${arr2[3]} ${arr2[4]}
    }
done

lastConfigTmpStr=`cat $lastConfigTmp`
lastConfigStr=`cat $lastConfig`
if [ "$firstAfterBoot" = "1" -o "$lastConfigTmpStr" != "$lastConfigStr" ];then
    echo '更新iptables规则[DOING]'
    source $lastConfigTmp
    cat $lastConfigTmp > $lastConfig
    echo '更新iptables规则[DONE]，新规则如下：'
    echo "###########################################################"
    iptables -L PREROUTING -n -t nat --line-number
    iptables -L POSTROUTING -n -t nat --line-number
    echo "###########################################################"
else
    echo "iptables规则未变更"
fi

firstAfterBoot=0
echo '' > $lastConfigTmp
sleep 60
echo ''
echo ''
echo ''
done    
AAAA
echo 

cat > /lib/systemd/system/dnat.service <<\EOF
[Unit]
Description=动态设置iptables转发规则
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/root/
EnvironmentFile=
ExecStart=/bin/bash /usr/local/bin/dnat.sh
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dnat > /dev/null 2>&1
service dnat stop > /dev/null 2>&1
service dnat start > /dev/null 2>&1
}

## 获取本机地址（仅作为参考）
localIP=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1 | grep -Ev '(^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.1[6-9]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.2[0-9]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.3[0-1]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$)')
if [ "${localIP}" = "" ]; then
    localIP=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1|head -n 1 )
fi

addDnat(){
    local localport=
    local remoteport=
    local remotehost=
    local interface=
    local source_ip=
    local valid=

    # 获取所有网络接口及其IP地址
    echo "可用的网络接口："
    interfaces=($(ip link show | grep -E '^[0-9]+:' | awk -F: '{print $2}' | tr -d ' ' | grep -v 'lo'))
    declare -A ip_map
    declare -A iface_map
    for i in "${!interfaces[@]}"; do
        iface="${interfaces[$i]}"
        ip=$(ip -4 addr show "$iface" | grep -oP 'inet \K[\d.]+' || echo "无IP")
        ip_map["$i"]="$ip"
        iface_map["$i"]="$iface"
        printf "%d. %s (IP: %s)\n" "$((i+1))" "$iface" "$ip"
    done

    echo -n "请选择本地网口 (输入序号，如 1): "
    read selection
    
    # 验证输入是否为有效序号
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#interfaces[@]}" ]; then
        echo -e "${red}无效的序号！请输入 1 到 ${#interfaces[@]} 之间的数字${black}"
        return 1
    fi

    # 获取选中的接口和IP
    interface="${iface_map[$((selection-1))]}"
    source_ip="${ip_map[$((selection-1))]}"
    if [ "$source_ip" = "无IP" ]; then
        echo -e "${red}所选接口 $interface 没有有效的IP地址！${black}"
        return 1
    fi

    echo -n "本地端口号:" ; read localport
    echo -n "远程端口号:" ; read remoteport
    
    # 判断端口是否为数字
    echo "$localport" | grep -qE '^[0-9]+$' && echo "$remoteport" | grep -qE '^[0-9]+$' || {
        echo -e "${red}本地端口和目标端口请输入数字！！${black}"
        return 1
    }

    echo -n "目标域名/IP:" ; read remotehost

    # 更新配置格式为 localport>interface>remotehost:remoteport>source_ip
    sed -i "s/^$localport>.*/$localport>$interface>$remotehost:$remoteport>$source_ip/g" $conf
    [ "$(cat $conf|grep "$localport>$interface>$remotehost:$remoteport>$source_ip")" = "" ] && {
        cat >> $conf <<LINE
$localport>$interface>$remotehost:$remoteport>$source_ip
LINE
    }
    echo "成功添加转发规则 $localport>$interface>$remotehost:$remoteport (源IP: $source_ip)"
    setupService
}

rmDnat(){
    local localport=
    echo -n "本地端口号:" ; read localport
    sed -i "/^$localport>.*/d" $conf
    echo "done!"
}

testVars(){
    local localport=$1
    local remotehost=$2
    local remoteport=$3
    # 判断端口是否为数字
    local valid=
    echo "$localport"|[ -n "`sed -n '/^[0-9][0-9]*$/p'`" ] && echo $remoteport |[ -n "`sed -n '/^[0-9][0-9]*$/p'`" ]||{
       return 1;
    }
}

lsDnat(){
    arr1=(`cat $conf`)
    for cell in ${arr1[@]}  
    do
        arr2=(`echo $cell|tr ":" " "|tr ">" " "`)  # arr2=localport interface remotehost remoteport source_ip
        # 过滤非法的行
        [ "${arr2[4]}" != "" -a "${arr2[5]}" = "" ] && testVars ${arr2[0]} ${arr2[2]} ${arr2[3]} && {
            echo "转发规则： ${arr2[0]}>${arr2[1]}>${arr2[2]}:${arr2[3]} (源IP: ${arr2[4]})"
        }
    done
}

echo -e "${red}你要做什么呢（请输入数字）？Ctrl+C 退出本脚本${black}"
select todo in 增加转发规则 删除转发规则 列出所有转发规则 查看当前iptables配置
do
    case $todo in
    增加转发规则)
        addDnat
        ;;
    删除转发规则)
        rmDnat
        ;;
    列出所有转发规则)
        lsDnat
        ;;
    查看当前iptables配置)
        echo "###########################################################"
        iptables -L PREROUTING -n -t nat --line-number
        iptables -L POSTROUTING -n -t nat --line-number
        echo "###########################################################"
        ;;
    *)
        echo "如果要退出，请按Ctrl+C"
        ;;
    esac
done