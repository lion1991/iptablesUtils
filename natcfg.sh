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
echo "# Modified by: Lion                                         #"
echo "# Date: 2025-03-07                                          #"
echo "# Github: https://github.com/lion1991/iptablesUtils         #"
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

# 获取网络接口和IP信息的通用函数
getInterfaces() {
    interfaces=($(ip link show | grep -E '^[0-9]+:' | awk -F: '{print $2}' | tr -d ' ' | grep -v 'lo'))
    declare -A ip_map
    declare -A iface_map
    
    echo "可用的网络接口："
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
    
    return 0
}

# 验证端口是否为数字的通用函数
testVars(){
    local localport=$1
    local remoteport=$2
    
    echo "$localport" | grep -qE '^[0-9]+$' && echo "$remoteport" | grep -qE '^[0-9]+$' || {
        echo -e "${red}本地端口和目标端口请输入数字！！${black}"
        return 1
    }
    return 0
}

addDnat(){
    local localport=
    local remoteport=
    local remotehost=
    local interface=
    local source_ip=

    # 获取网络接口信息
    getInterfaces || return 1

    echo -n "本地端口号:" ; read localport
    echo -n "远程端口号:" ; read remoteport
    
    # 判断端口是否为数字
    testVars "$localport" "$remoteport" || return 1

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

addBatchDnat(){
    local local_port_range=
    local remote_port_range=
    local remotehost=
    local interface=
    local source_ip=
    local local_start=
    local local_end=
    local remote_start=
    local remote_end=

    # 获取网络接口信息
    getInterfaces || return 1

    echo -n "本地端口范围 (格式: 起始端口:结束端口, 如 10000:10010): "; read local_port_range
    echo -n "远程端口范围 (格式: 起始端口:结束端口, 如 20000:20010): "; read remote_port_range
    echo -n "目标域名/IP: "; read remotehost

    # 解析端口范围
    local_start=$(echo $local_port_range | cut -d: -f1)
    local_end=$(echo $local_port_range | cut -d: -f2)
    remote_start=$(echo $remote_port_range | cut -d: -f1)
    remote_end=$(echo $remote_port_range | cut -d: -f2)

    # 验证端口范围格式
    if ! [[ "$local_start" =~ ^[0-9]+$ ]] || ! [[ "$local_end" =~ ^[0-9]+$ ]] || \
       ! [[ "$remote_start" =~ ^[0-9]+$ ]] || ! [[ "$remote_end" =~ ^[0-9]+$ ]]; then
        echo -e "${red}端口范围格式错误！请使用数字:数字的格式${black}"
        return 1
    fi

    # 验证两个范围包含相同数量的端口
    local local_count=$((local_end - local_start + 1))
    local remote_count=$((remote_end - remote_start + 1))
    
    if [ $local_count -le 0 ] || [ $remote_count -le 0 ]; then
        echo -e "${red}端口范围无效！结束端口必须大于等于起始端口${black}"
        return 1
    fi
    
    if [ $local_count -ne $remote_count ]; then
        echo -e "${red}本地端口范围和远程端口范围必须包含相同数量的端口${black}"
        return 1
    fi

    # 批量添加转发规则
    echo "正在添加以下批量转发规则:"
    local localport=$local_start
    local remoteport=$remote_start
    
    while [ $localport -le $local_end ]; do
        echo "转发 $localport 到 $remotehost:$remoteport (通过 $interface, 源IP: $source_ip)"
        
        # 更新配置
        sed -i "s/^$localport>.*/$localport>$interface>$remotehost:$remoteport>$source_ip/g" $conf
        [ "$(cat $conf|grep "$localport>$interface>$remotehost:$remoteport>$source_ip")" = "" ] && {
            cat >> $conf <<LINE
$localport>$interface>$remotehost:$remoteport>$source_ip
LINE
        }
        
        # 递增端口
        localport=$((localport + 1))
        remoteport=$((remoteport + 1))
    done
    
    echo "成功添加 $local_count 条转发规则"
    setupService
}

rmDnat(){
    # 列出所有规则并显示编号
    rules=()
    i=1
    echo -e "${red}当前转发规则列表：${black}"
    echo -e "----------------------------------------"
    while read line; do
        if [ -n "$line" ]; then
            rules+=("$line")
            arr=(`echo $line|tr ":" " "|tr ">" " "`)
            echo -e "${red}[$i]${black} 本地端口: ${arr[0]} → 目标: ${arr[2]}:${arr[3]} (网口: ${arr[1]}, 源IP: ${arr[4]})"
            ((i++))
        fi
    done < $conf
    
    if [ ${#rules[@]} -eq 0 ]; then
        echo -e "${red}没有找到任何转发规则!${black}"
        return 1
    fi
    
    echo -e "----------------------------------------"
    echo -e "请输入要删除的规则编号 (格式说明: "
    echo -e "  - 单个规则: 输入数字，如 \"3\""
    echo -e "  - 多个规则: 用空格分隔，如 \"1 3 5\""
    echo -e "  - 连续规则: 用连字符表示范围，如 \"2-5\""
    echo -e "  - 混合输入: 如 \"1 3-5 7 9-11\""
    echo -e "  - 输入 0 返回主菜单)"
    echo -n "请输入: "
    read input
    
    # 检查是否选择返回主菜单
    if [[ "$input" == "0" ]]; then
        echo "返回主菜单"
        return 0
    fi
    
    # 解析输入，处理范围表示法和单个数字
    selections=()
    for item in $input; do
        if [[ "$item" == *-* ]]; then
            # 处理范围格式 (例如 "3-7")
            start=$(echo $item | cut -d'-' -f1)
            end=$(echo $item | cut -d'-' -f2)
            
            # 验证范围有效性
            if ! [[ "$start" =~ ^[0-9]+$ ]] || ! [[ "$end" =~ ^[0-9]+$ ]]; then
                echo -e "${red}无效的范围格式: $item, 请使用数字-数字的格式${black}"
                return 1
            fi
            
            if [ $start -gt $end ]; then
                echo -e "${red}无效的范围: $item, 起始值不能大于结束值${black}"
                return 1
            fi
            
            # 添加范围内的所有编号
            for ((num=start; num<=end; num++)); do
                selections+=($num)
            done
        else
            # 处理单个数字
            if ! [[ "$item" =~ ^[0-9]+$ ]]; then
                echo -e "${red}无效的编号: $item, 请输入数字${black}"
                return 1
            fi
            selections+=($item)
        fi
    done
    
    if [ ${#selections[@]} -eq 0 ]; then
        echo "未选择任何规则，操作取消"
        return 0
    fi
    
    # 验证选择的规则编号是否有效
    valid=1
    for sel in "${selections[@]}"; do
        if [ $sel -lt 1 ] || [ $sel -gt ${#rules[@]} ]; then
            echo -e "${red}规则编号 $sel 超出有效范围 (1-${#rules[@]})${black}"
            valid=0
            break
        fi
    done
    
    if [ $valid -eq 0 ]; then
        return 1
    fi
    
    # 去重并排序选择的规则编号
    # Bash 4.0+ 可以直接使用关联数组去重
    declare -A unique_selections
    for sel in "${selections[@]}"; do
        unique_selections[$sel]=1
    done
    
    # 将去重后的编号转换回数组并排序
    selections=()
    for sel in "${!unique_selections[@]}"; do
        selections+=($sel)
    done
    # 对数组进行数值排序
    selections=($(for i in "${selections[@]}"; do echo $i; done | sort -n))
    
    echo -e "${red}将删除以下规则:${black}"
    for sel in "${selections[@]}"; do
        rule="${rules[$((sel-1))]}"
        arr=(`echo $rule|tr ":" " "|tr ">" " "`)
        echo "- 本地端口: ${arr[0]} → 目标: ${arr[2]}:${arr[3]} (网口: ${arr[1]}, 源IP: ${arr[4]})"
    done
    
    read -p "确认删除这 ${#selections[@]} 条规则? [y/n]: " confirm
    if [[ $confirm == [yY] ]]; then
        for sel in "${selections[@]}"; do
            rule="${rules[$((sel-1))]}"
            port=$(echo $rule | cut -d'>' -f1)
            sed -i "/^$port>.*/d" $conf
        done
        echo -e "${red}已删除选中的 ${#selections[@]} 条规则!${black}"
        setupService
    else
        echo "已取消删除操作"
    fi
}

lsDnat(){
    i=1
    echo -e "${red}当前转发规则列表：${black}"
    echo -e "----------------------------------------"
    
    arr1=(`cat $conf`)
    for cell in ${arr1[@]}  
    do
        arr2=(`echo $cell|tr ":" " "|tr ">" " "`)  # arr2=localport interface remotehost remoteport source_ip
        # 过滤非法的行
        [ "${arr2[4]}" != "" -a "${arr2[5]}" = "" ] && testVars ${arr2[0]} ${arr2[3]} && {
            echo -e "${red}[$i]${black} 本地端口: ${arr2[0]} → 目标: ${arr2[2]}:${arr2[3]} (网口: ${arr2[1]}, 源IP: ${arr2[4]})"
            ((i++))
        }
    done
    
    if [ $i -eq 1 ]; then
        echo "当前没有转发规则"
    fi
    echo -e "----------------------------------------"
}

echo
echo -e "${red}================ iptables端口转发管理工具 =================${black}"
echo "请选择要执行的操作（输入数字并回车）："
echo
echo -e "  ${red}[1]${black} 增加单条转发规则     ${red}[3]${black} 列出所有转发规则"
echo -e "  ${red}[2]${black} 删除转发规则         ${red}[4]${black} 查看当前iptables配置"
echo -e "  ${red}[5]${black} 批量添加转发规则"
echo
echo -e "输入 ${red}Ctrl+C${black} 退出本脚本"
echo -e "${red}=======================================================${black}"
echo

select todo in 增加转发规则 删除转发规则 列出所有转发规则 查看当前iptables配置 批量添加转发规则
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
    批量添加转发规则)
        addBatchDnat
        ;;
    *)
        echo "如果要退出，请按Ctrl+C"
        ;;
    esac
done