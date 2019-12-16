#!/bin/bash -e

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi

command_exists()
{
	command -v "$1" >/dev/null 2>&1
}

for cmd in debootstrap unzip
do
	if ! command_exists $cmd; then
		echo Your system does not have $cmd, install it first, please wait.
		apt update >/dev/null 2>&1 && apt install -y $cmd >/dev/null 2>&1
	fi
done

mount_dir=/mnt/debian

dev="$1"
[[ ! -b "$dev" ]] && echo disk $dev must be a block device,like /dev/vda. && exit 2
devsize=$(fdisk -l | grep $dev | awk '{sub(/,/,"",$4);print $3$4;exit}')


set_hostname="$2"
set_address="$3"
set_netmask="$4"
set_gateway="$5"
rootpwd=$(openssl rand -base64 27)

live_ip=$(ip route get 8.8.8.8 | awk '{print $NF; exit}')
auto_hostname="debian-""${live_ip//./-}"
[[ -n "$set_hostname" ]] && use_hostname=$set_hostname || use_hostname=$auto_hostname
[[ -z "$set_address" ]] && ip_msg="DHCP" || ip_msg=$set_address
[[ -z "$set_netmask" ]] && nm_msg="DHCP" || nm_msg=$set_netmask
[[ -z "$set_gateway" ]] && gw_msg="DHCP" || gw_msg=$set_gateway

echo ===========================
echo Install Debian Sid to:
echo "disk: ""$dev ""$devsize"
echo "hostname: ""$use_hostname"
echo "address: ""$ip_msg"
echo "netmask: ""$nm_msg"
echo "gateway: ""$gw_msg"
echo ===========================

DEFAULT="y"
read -e -p "Are You Sure? [Y/n] " input
input="${input:-${DEFAULT}}"
case $input in
		[yY][eE][sS]|[yY])
		echo "GoGoGo ..."
	;;
	*)
		echo "Error ..."
		exit 3
	;;
esac

echo Format $dev ...
mkdir -p ${mount_dir}
if mountpoint ${mount_dir} >/dev/null; then
	umount ${mount_dir}
fi

mkfs.ext4 -F -L debian-root -b 1024 -I 128 -O "^has_journal" $dev >/dev/null 2>&1

echo Mount $dev to ${mount_dir} ...
mount $dev ${mount_dir}

echo Install debian to ${mount_dir} ...
/usr/sbin/debootstrap --no-check-gpg --exclude=unattended-upgrades,apparmor --include=bash-completion,iproute2 sid /mnt/debian http://ftp.us.debian.org/debian

echo Install V2ray ...
VER=$(wget --no-check-certificate -q -O- https://api.github.com/repos/v2ray/v2ray-core/releases/latest | awk -F'"' '/tag_name/ {print $4}')
URL=https://github.com/v2ray/v2ray-core/releases/download/$VER/v2ray-linux-32.zip
wget --no-check-certificate -q -O /tmp/v2ray.zip $URL
unzip -q /tmp/v2ray.zip -d ${mount_dir}/usr/sbin v2ray v2ctl
chmod +x ${mount_dir}/usr/sbin/{v2ray,v2ctl}

UUID=$(cat /proc/sys/kernel/random/uuid)
mkdir ${mount_dir}/etc/v2ray
cat << EOF > ${mount_dir}/etc/v2ray/config.json
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [  {
    "port": 1024,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$UUID",
        "alterId": 100
      }]
    },
    "streamSettings": {
      "network": "ws"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF

cat << EOF > ${mount_dir}/etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray Server
ConditionFileNotEmpty=/etc/v2ray/config.json
After=network.target

[Service]
Type=simple
DynamicUser=yes
ProtectHome=yes
NoNewPrivileges=yes
ExecStartPre=/usr/sbin/v2ray -config /etc/v2ray/config.json -test
ExecStart=/usr/sbin/v2ray -config /etc/v2ray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo Config system ...
mount /dev ${mount_dir}/dev --bind
mount -o remount,ro,bind ${mount_dir}/dev

mount -t proc none ${mount_dir}/proc
mount -o bind /sys ${mount_dir}/sys

echo "$use_hostname" > ${mount_dir}/etc/hostname
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > ${mount_dir}/etc/resolv.conf
echo tcp_bbr >> ${mount_dir}/etc/modules
sed -i '/src/d' ${mount_dir}/etc/apt/sources.list

mask2cidr ()
{
	local x=${1##*255.}
	set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
	x=${1%%$3*}
	echo $(( $2 + (${#x}/4) ))
}

if [ -n "$set_address" -o -n "$set_netmask" -o -n "$set_gatway" ]
then
	set_cidr=$(mask2cidr $set_netmask)
	cat << EOF > ${mount_dir}/etc/systemd/network/20-wired.network
[Match]
Name=en*

[Network]
Address=$set_address/$set_cidr
Gateway=$set_gateway
EOF
else
	cat << EOF > ${mount_dir}/etc/network/interfaces
[Match]
Name=en*

[Network]
DHCP=ipv4
EOF
fi

cat << EOF > ${mount_dir}/etc/fstab
LABEL=debian-root /        ext4  defaults,noatime                            0 0
tmpfs             /tmp     tmpfs mode=1777,strictatime,nosuid,nodev,size=90% 0 0
tmpfs             /var/log tmpfs defaults,noatime                            0 0
EOF

mkdir -p ${mount_dir}/root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDyuzRtZAyeU3VGDKsGk52rd7b/rJ/EnT8Ce2hwWOZWp" >> ${mount_dir}/root/.ssh/authorized_keys
chmod 600 ${mount_dir}/root/.ssh/authorized_keys

mkdir -p ${mount_dir}/etc/apt/apt.conf.d
cat << EOF > ${mount_dir}/etc/apt/apt.conf.d/99-freedisk
APT::Authentication "0";
APT::Get::AllowUnauthenticated "1";
Dir::Cache "/dev/shm";
Dir::State::lists "/dev/shm";
Dir::Log "/dev/shm";
DPkg::Post-Invoke {"/bin/rm -f /dev/shm/archives/*.deb || true";};
EOF

mkdir -p ${mount_dir}/etc/dpkg/dpkg.cfg.d
cat << EOF > ${mount_dir}/etc/dpkg/dpkg.cfg.d/99-nodoc
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/groff/*
path-exclude /usr/share/info/*
path-exclude /usr/share/lintian/*
path-exclude /usr/share/linda/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
EOF

mkdir -p ${mount_dir}/etc/systemd/journald.conf.d
cat << EOF > ${mount_dir}/etc/systemd/journald.conf.d/storage.conf
[Journal]
Storage=volatile
EOF

sed -i 's/#\?\(PerminRootLogin\s*\).*$/\1 yes/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PubkeyAuthentication\s*\).*$/\1 yes/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PermitEmptyPasswords\s*\).*$/\1 no/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PasswordAuthentication\s*\).*$/\1 no/' ${mount_dir}/etc/ssh/sshd_config

mkdir -p ${mount_dir}/etc/systemd/system/ssh.socket.d
cat << EOF > ${mount_dir}/etc/systemd/system/ssh.socket.d/port.conf
[Socket]
ListenStream=
ListenStream=127.0.0.1:22
EOF

mkdir -p ${mount_dir}/etc/systemd/system.conf.d
cat << EOF > ${mount_dir}/etc/systemd/system.conf.d/python.conf
[Manager]
DefaultEnvironment=PYTHONDONTWRITEBYTECODE=1
EOF

cat << EOF > ${mount_dir}/etc/profile.d/python.sh
export PYTHONDONTWRITEBYTECODE=1
EOF

cat << EOF > ${mount_dir}/etc/pip.conf
[global]
download-cache=/tmp
cache-dir=/tmp
EOF

cat << EOF >> ${mount_dir}/root/.bashrc

export HISTSIZE=1000
export LESSHISTFILE=/dev/null
unset HISTFILE
EOF

cat << EOF > ${mount_dir}/etc/sysctl.d/10-tcp_bbr.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

cat << EOF > ${mount_dir}/etc/sysctl.d/20-security.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 5
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_ignore_all = 1
EOF

cat << EOF > ${mount_dir}/etc/default/grub
GRUB_DEFAULT=0
GRUB_HIDDEN_TIMEOUT_QUIET=false
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet ipv6.disable=1 module_blacklist=ipv6,nf_defrag_ipv6"
GRUB_CMDLINE_LINUX="acpi_osi=Linux"
EOF

chroot ${mount_dir} /bin/bash -c "
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
echo root:$rootpwd | chpasswd
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
mkdir /tmp/apt
DEBIAN_FRONTEND=noninteractive apt -o Dir::Cache=/tmp/apt -o Dir::State::lists=/tmp/apt update
DEBIAN_FRONTEND=noninteractive apt -o Dir::Cache=/tmp/apt -o Dir::State::lists=/tmp/apt install -y -qq linux-image-cloud-amd64 grub2
grub-install --force $dev
update-grub

systemctl enable systemd-networkd ssh.socket v2ray
systemctl disable ssh.service
systemctl -f mask apt-daily.timer apt-daily-upgrade.timer fstrim.timer motd-news.timer
sleep 2
rm -rf /tmp/apt /var/log/* /usr/share/doc/* /usr/share/man/* /tmp/* /var/tmp/* /var/cache/apt/*
find /usr/lib/python* /usr/local/lib/python* /usr/share/python* -type f -name "*.py[co]" -o -type d -name __pycache__ -exec rm -rf {} \;
find /usr/share/locale -mindepth 1 -maxdepth 1 ! -name 'en' -exec rm -rf {} \;
find /usr/share/zoneinfo -mindepth 1 -maxdepth 2 ! -name 'UTC' -a ! -name 'UCT' -a ! -name 'PRC' -a ! -name 'Asia' -a ! -name '*Shanghai' -exec rm -rf {} \;
"

umount ${mount_dir}/dev ${mount_dir}/proc ${mount_dir}/sys/fs/fuse/connections ${mount_dir}/sys
sleep 1
umount ${mount_dir}

echo Done.
echo ===================================================
echo "Root password: $rootpwd"
echo "V2ray UUID   : $UUID"
echo ===================================================
