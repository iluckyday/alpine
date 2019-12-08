#!/bin/bash -e

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi

command_exists()
{
	command -v "$1" >/dev/null 2>&1
}

for cmd in wget unzip
do
	if ! command_exists $cmd; then
		echo Your system does not have $cmd, install it first, please wait.
		apt update >/dev/null 2>&1 && apt install -y $cmd >/dev/null 2>&1
	fi
done

mount_dir=/mnt/alpine

dev="$1"
[[ ! -b "$dev" ]] && echo disk $dev must be a block device,like /dev/vda. && exit 2
devsize=$(fdisk -l | grep $dev | awk '{sub(/,/,"",$4);print $3$4}')


set_hostname="$2"
set_address="$3"
set_netmask="$4"
set_gateway="$5"
rootpwd=$(openssl rand -base64 27)
sspwd=$(openssl rand -base64 27)

live_ip=$(ip route get 8.8.8.8 | awk '{print $NF; exit}')
auto_hostname="alpine-""${live_ip//./-}"
[[ -n "$set_hostname" ]] && use_hostname=$set_hostname || use_hostname=$auto_hostname
[[ -z "$set_address" ]] && ip_msg="DHCP" || ip_msg=$set_address
[[ -z "$set_netmask" ]] && nm_msg="DHCP" || nm_msg=$set_netmask
[[ -z "$set_gateway" ]] && gw_msg="DHCP" || gw_msg=$set_gateway

echo ===========================
echo Install Alpine Linux edge
echo "harddisk: ""$dev""$devsize"
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

mkfs.ext4 -F -L alpine-root -b 1024 -I 128 -O "^has_journal" $dev >/dev/null 2>&1

echo Mount $dev to ${mount_dir} ...
mount $dev ${mount_dir}

echo Download apk-tools-static ...
ver=$(wget -qO- https://pkgs.alpinelinux.org/package/edge/main/x86/apk-tools-static | awk -F'>' '/Flagged:/ {sub(/<\/a/,"",$2);print$2}')
wget -qO- http://dl-cdn.alpinelinux.org/alpine/edge/main/x86/apk-tools-static-$ver.apk | tar -xz -C /tmp

echo Install alpine-base to ${mount_dir} ...
/tmp/sbin/apk.static --update --no-cache --arch x86 -q -X http://dl-cdn.alpinelinux.org/alpine/edge/main -U --allow-untrusted --root ${mount_dir} --initdb add alpine-base dropbear

echo Install V2ray ...
VER=$(wget --no-check-certificate -q -O- https://api.github.com/repos/v2ray/v2ray-core/releases/latest | awk -F'"' '/tag_name/ {print $4}')
URL=https://github.com/v2ray/v2ray-core/releases/download/$VER/v2ray-linux-32.zip
wget --no-check-certificate -q -O /tmp/v2ray.zip $URL
unzip -q /tmp/v2ray.zip -d ${mount_dir}/usr/sbin v2ray v2ctl
chmod +x ${mount_dir}/usr/sbin/{v2ray,v2ctl}

UUID=$(chroot ${mount_dir} /usr/sbin/v2ctl uuid)
mkdir ${mount_dir}/etc/v2ray
cat << EOF > ${mount_dir}/etc/v2ray/config.json
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [{
    "protocol": "shadowsocks",
    "port": 7117,
    "settings": {
      "method": "aes-256-cfb",
      "password": "$sspwd",
      "udp": false,
      "ota": false
      }
  },
  {
    "protocol": "vmess",
    "port": 8118,
    "settings": {
      "clients": [{
        "id": "$UUID",
        "alterId": 100
      }]
    }
  },
  {
    "protocol": "vmess",
    "port": 8118,
    "settings": {
      "clients": [{
        "id": "$UUID",
        "alterId": 100
      }]
    },
    "streamSettings": {
      "network": "kcp"
    }
  },
  {
    "protocol": "vmess",
    "port": 9119,
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

cat << EOF > ${mount_dir}/etc/init.d/v2ray
#!/sbin/openrc-run

name="V2Ray Server"
command="/usr/sbin/v2ray"
command_args="-config /etc/v2ray/config.json"
command_background=yes
command_user=nobody:nobody
pidfile="/var/run/v2ray.pid"

depend() {
	need net localmount
	after firewall
}
EOF
chmod +x ${mount_dir}/etc/init.d/v2ray

echo Config system ...
mount /dev ${mount_dir}/dev --bind
mount -o remount,ro,bind ${mount_dir}/dev

mount -t proc none ${mount_dir}/proc
mount -o bind /sys ${mount_dir}/sys

echo "$use_hostname" > ${mount_dir}/etc/hostname
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > ${mount_dir}/etc/resolv.conf
echo tcp_bbr >> ${mount_dir}/etc/modules
echo -e "http://dl-cdn.alpinelinux.org/alpine/edge/main\nhttp://dl-cdn.alpinelinux.org/alpine/edge/community\nhttp://dl-cdn.alpinelinux.org/alpine/edge/testing" > ${mount_dir}/etc/apk/repositories

rm -f ${mount_dir}/etc/sysctl.d/00-alpine.conf ${mount_dir}/etc/motd ${mount_dir}/etc/init.d/crond ${mount_dir}/etc/init.d/klogd ${mount_dir}/etc/init.d/syslog

mkdir -p ${mount_dir}/root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDGgRpNtXJb41ZIiZaWblqsH3dCNOiPTMUiQeSR8rPHnr79ugX+OTl+jihIEwoB+0MFQcRuRuxTY5/ceyfQke5sDiPBefU7FGSy2ATwLgbe8mAmgf3tn20GKHYBJNiI58bHx+q35G4r8sJg8aDCPC30JCTr8EBmUX9oVqHLLe69e20T/pE1YcoR7y8fJaimrapwmB22HHmWr/M9fb3BDhtvIwveRgxbnEJzVbtfbWNx6Dtzm/6XGBRKwe+tLdbE5+v1JWQwT9ItyfIgq1aH0FJUvv/d6EAS6thdtkyPoU7orqJhA72H/YmusMFxqzRns60Rxo3Ngnwd39p/kPv81aO9XNPW2ICEeItqE8L8Y6eXmSuK20aMpyY2XzzGNPzRp2pyNDX1pPmCdOqN0zAv4eAQaX5Yq2uZ5VFC2e0eAPR6bWePUHrkENNRjTlIDPMOl3mOJSmgGBu0N5EPvWUBqhPifHrJI9It95ru+UPvxWpA4fo0mU1uOWcqQVWNGH/8Ti5Sb424iK5P3OpivQOwzAJXvbrr47+qW3eOW11cHWj5VD899YWXkzASG646yYIa34zpw4kNzIhCLXI1lOnaxVOM7UuTi7P5gWFFAVmrCAFoOhh1tYYLDDbBjAHzHgTvU1L1WYGUlIK/BFnWh6wt/G8CV24ALPSyuVVOvbdIj2jOnQ==" >> ${mount_dir}/root/.ssh/authorized_keys
chmod 600 ${mount_dir}/root/.ssh/authorized_keys

cat << EOF > ${mount_dir}/etc/inittab
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
tty1::respawn:/sbin/getty 38400 tty1
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

if [ -n "$set_address" -o -n "$set_netmask" -o -n "$set_gatway" ]
then
	cat << EOF > ${mount_dir}/etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
	address $set_address
	netmask $set_netmask
	gateway $set_gateway
EOF
else
	cat << EOF > ${mount_dir}/etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF
fi

cat << EOF > ${mount_dir}/etc/fstab
LABEL=alpine-root /    ext4  defaults,noatime                            0 0
tmpfs             /tmp tmpfs mode=1777,strictatime,nosuid,nodev,size=90% 0 0
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

cat << EOF > ${mount_dir}/etc/update-extlinux.conf
overwrite=1
vesa_menu=0
default_kernel_opts="ipv6.disable=1 quiet rootfstype=ext4 module_blacklist=psmouse,mousedev,floppy,hid_generic,usbhid,hid,sr_mod,cdrom,uhci_hcd,ehci_pci,ehci_hcd,usbcore,usb_common,drm_kms_helper,syscopyarea,sysimgblt,fs_sys_fops,drm,drm_panel_orientation_quirks,firmware_class,cfbfillrect,cfbimgblt,cfbcopyarea,fb,fbdev,loop"
modules=ext4
root=LABEL=alpine-root
verbose=0
timeout=1
hidden=0
prompt=0
EOF

cat << EOF > ${mount_dir}/etc/conf.d/dropbear
DROPBEAR_OPTS="-s -p 127.0.0.1:22"
EOF

chroot ${mount_dir} /bin/sh -c "
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
echo root:$rootpwd | chpasswd
apk add --update --no-cache syslinux linux-virt
dd bs=440 count=1 conv=notrunc if=/usr/share/syslinux/mbr.bin of=$dev
extlinux -i /boot

rc-update add devfs sysinit
rc-update add mdev sysinit
rc-update add hwdrivers sysinit  # need for e1000 driver load
rc-update add modules boot
rc-update add sysctl boot
rc-update add hostname boot
rc-update add bootmisc boot
rc-update add networking boot
rc-update add urandom boot
rc-update add dropbear
rc-update add v2ray
rc-update add mount-ro shutdown
rc-update add killprocs shutdown
"

umount ${mount_dir}/dev ${mount_dir}/proc ${mount_dir}/sys
sleep 1
umount ${mount_dir}

echo Done.
echo ===================================================
echo Root password: $rootpwd
echo Ss   password: $rootpwd
echo V2ray UUID is: $UUID
echo ===================================================
