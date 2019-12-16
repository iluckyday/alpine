#!/bin/bash -e

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi

command_exists()
{
	command -v "$1" >/dev/null 2>&1
}

for cmd in debootstrap
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
/usr/sbin/debootstrap --no-check-gpg --components=main,contrib,non-free --exclude=unattended-upgrades --include=bash-completion,iproute2 sid /mnt/debian http://ftp.us.debian.org/debian

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
LABEL=debian-root /    ext4  defaults,noatime                            0 0
tmpfs             /tmp tmpfs mode=1777,strictatime,nosuid,nodev,size=90% 0 0
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

cat << EOF > ${mount_dir}/etc/update-extlinux.conf
overwrite=1
vesa_menu=0
default_kernel_opts="ipv6.disable=1 quiet rootfstype=ext4 module_blacklist=ipv6,nf_defrag_ipv6,psmouse,mousedev,floppy,hid_generic,usbhid,hid,sr_mod,cdrom,uhci_hcd,ehci_pci,ehci_hcd,usbcore,usb_common,drm_kms_helper,syscopyarea,sysimgblt,fs_sys_fops,drm,drm_panel_orientation_quirks,firmware_class,cfbfillrect,cfbimgblt,cfbcopyarea,fb,fbdev,loop"
modules=ext4
root=LABEL=debian-root
verbose=0
timeout=1
hidden=0
prompt=0
EOF

chroot ${mount_dir} /bin/bash -c "
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
echo root:$rootpwd | chpasswd
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
apt update -y
apt install -y -qq linux-image-cloud-amd64 extlinux
dd bs=440 count=1 conv=notrunc if=/usr/lib/EXTLINUX/mbr.bin of=$dev
extlinux -i /boot

systemctl enable systemd-networkd
"

umount ${mount_dir}/dev ${mount_dir}/proc ${mount_dir}/sys
sleep 1
umount ${mount_dir}

echo Done.
echo ===================================================
echo "SSH Server Available:"
echo "Root password: $rootpwd"
echo ===================================================
