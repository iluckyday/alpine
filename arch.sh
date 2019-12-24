#!/bin/bash -e

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi

hname=$(hostname)
if [ "$hname" != "archiso" ]
then
	echo "This script must be run in archiso" 1>&2
	exit 2
fi

mount_dir=/mnt/arch

dev="$1"
[[ ! -b "$dev" ]] && echo disk $dev must be a block device,like /dev/vda. && exit 2
devsize=$(fdisk -l | grep $dev | awk '{sub(/,/,"",$4);print $3$4;exit}')

set_hostname="$2"
set_address="$3"
set_netmask="$4"
set_gateway="$5"
rootpwd=$(openssl rand -base64 27)

live_ip=$(ip route get 8.8.8.8 | awk '{print $NF; exit}')
auto_hostname="arch-""${live_ip//./-}"
[[ -n "$set_hostname" ]] && use_hostname=$set_hostname || use_hostname=$auto_hostname
[[ -z "$set_address" ]] && ip_msg="DHCP" || ip_msg=$set_address
[[ -z "$set_netmask" ]] && nm_msg="DHCP" || nm_msg=$set_netmask
[[ -z "$set_gateway" ]] && gw_msg="DHCP" || gw_msg=$set_gateway

echo ===========================
echo Install Arch Linux to:
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

mkfs.ext4 -F -L arch-root -b 1024 -I 128 -O "^has_journal" $dev >/dev/null 2>&1

echo Mount $dev to ${mount_dir} ...
mount $dev ${mount_dir}

echo Install arch to ${mount_dir} ...
cat << "EOF" > /etc/pacman.d/mirrorlist
Server = http://mirror.rackspace.com/archlinux/$repo/os/$arch
EOF
/usr/bin/pacstrap -i -c /mnt/arch base vim tmux bash-completion openssh --noconfirm --cachedir /tmp --ignore dhcpcd --ignore logrotate --ignore nano --ignore netctl --ignore usbutils --ignore vi --ignore s-nail

echo Install V2ray ...
VER=$(curl -skL https://api.github.com/repos/v2ray/v2ray-core/releases/latest | awk -F'"' '/tag_name/ {print $4}')
URL=https://github.com/v2ray/v2ray-core/releases/download/$VER/v2ray-linux-32.zip
curl -skL $URL | /usr/lib/initcpio/busybox unzip - -q -d ${mount_dir}/usr/local/sbin v2ray v2ctl
chmod +x ${mount_dir}/usr/local/sbin/{v2ray,v2ctl}

UUID=$(cat /proc/sys/kernel/random/uuid)
mkdir ${mount_dir}/etc/v2ray
cat << EOF > ${mount_dir}/etc/v2ray/config.json
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [  {
    "port": 9119,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$UUID",
        "alterId": 100
      }]
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
DynamicUser=yes
ProtectHome=yes
NoNewPrivileges=yes
ExecStart=/usr/local/sbin/v2ray -config /etc/v2ray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo Config system ...
mount /dev ${mount_dir}/dev --bind
mount -o remount,ro,bind ${mount_dir}/dev

mount -o bind /proc ${mount_dir}/proc
mount -o bind /sys ${mount_dir}/sys
mount -o bind /tmp ${mount_dir}/tmp

echo "$use_hostname" > ${mount_dir}/etc/hostname
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > ${mount_dir}/etc/resolv.conf

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
	cat << EOF > ${mount_dir}/etc/systemd/network/20-wired.network
[Match]
Name=en*

[Network]
DHCP=ipv4
EOF
fi

cat << EOF > ${mount_dir}/etc/fstab
LABEL=arch-root   /                    ext4  defaults,noatime                            0 0
tmpfs             /tmp                 tmpfs mode=1777,strictatime,nosuid,nodev,size=90% 0 0
tmpfs             /var/log             tmpfs defaults,noatime                            0 0
tmpfs             /root/.cache         tmpfs defaults,noatime                            0 0
tmpfs             /var/cache/pacman    tmpfs defaults,noatime                            0 0
tmpfs             /var/lib/pacman/sync tmpfs defaults,noatime                            0 0
EOF

mkdir -p ${mount_dir}/root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDyuzRtZAyeU3VGDKsGk52rd7b/rJ/EnT8Ce2hwWOZWp" >> ${mount_dir}/root/.ssh/authorized_keys
chmod 600 ${mount_dir}/root/.ssh/authorized_keys

cp ${mount_dir}/etc/skel/.bash_profile ${mount_dir}/root

cat << EOF > ${mount_dir}/root/.vimrc
syntax on
filetype on
set nu
set history=0
set autoread
set backupdir=/dev/shm//
set directory=/dev/shm//
set undodir=/dev/shm//
set nobackup
set nowritebackup
set cursorline
highlight CursorLine   cterm=NONE ctermbg=darkred ctermfg=white guibg=darkred guifg=white
highlight CursorColumn cterm=NONE ctermbg=darkred ctermfg=white guibg=darkred guifg=white
set showmatch
set ignorecase
set hlsearch
set incsearch
set tabstop=4
set softtabstop=4
set shiftwidth=4
set nowrap
set wildmenu
set wildmode=longest:full,full
let skip_defaults_vim=1
set viminfo=
set encoding=utf8
set fileencodings=utf8,gb2312,gb18030,ucs-bom,latin1

:map <F10> :set invpaste<CR>
EOF

cat << "EOF" > ${mount_dir}/root/.tmux.conf
set-option -g mouse on

set -g default-terminal screen
set -g update-environment 'DISPLAY SSH_ASKPASS SSH_AGENT_PID SSH_CONNECTION WINDOWID XAUTHORITY TERM'
if "[[ ${TERM} =~ 256color || ${TERM} == fbterm ]]" 'set -g default-terminal screen-256color'

set -g terminal-overrides 'xterm*:smcup@:rmcup@'
set -g terminal-overrides 'xterm*disallowedWindowOps: 20,21,SetXprop'

setw -g mode-keys vi
EOF

mkdir -p ${mount_dir}/etc/systemd/journald.conf.d
cat << EOF > ${mount_dir}/etc/systemd/journald.conf.d/storage.conf
[Journal]
Storage=volatile
EOF

mkdir -p ${mount_dir}/etc/systemd/resolved.conf.d
cat << EOF > ${mount_dir}/etc/systemd/resolved.conf.d/llmnr.conf
[Resolve]
LLMNR=no
EOF

mkdir -p ${mount_dir}/etc/systemd/system-environment-generators
cat << EOF > ${mount_dir}/etc/systemd/system-environment-generators/20-python.sh
#!/bin/sh

echo 'PYTHONDONTWRITEBYTECODE=1'
EOF
chmod +x ${mount_dir}/etc/systemd/system-environment-generators/20-python.sh

mkdir -p ${mount_dir}/etc/systemd/system-generators
cat << "EOF" > ${mount_dir}/etc/systemd/system-generators/masked-unit-generator
#!/bin/sh

set -eu

gendir="$1"

while IFS= read -r line
do
  if [ -n "$line" ]; then
    ln -sf "/dev/null" "$gendir/$line"
  fi
done < /etc/systemd/system/masked.units

exit 0
EOF
chmod +x ${mount_dir}/etc/systemd/system-generators/masked-unit-generator

cat << EOF > ${mount_dir}/etc/systemd/system/masked.units
lvm2-lvmetad.service
lvm2-monitor.service
systemd-journal-flush.service
systemd-update-utmp.service

lvm2-lvmetad.socket

man-db.timer
shadow.timer

dev-hugepages.mount
sys-kernel-debug.mount
EOF

sed -i 's/#\?\(ListenAddress 0.0.0.0\s*\).*$/ListenAddress 127.0.0.1/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PerminRootLogin\s*\).*$/\1 yes/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PubkeyAuthentication\s*\).*$/\1 yes/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PermitEmptyPasswords\s*\).*$/\1 no/' ${mount_dir}/etc/ssh/sshd_config
sed -i 's/#\?\(PasswordAuthentication\s*\).*$/\1 no/' ${mount_dir}/etc/ssh/sshd_config

cat << "EOF" >> ${mount_dir}/root/.bashrc

export HISTSIZE=1000
export LESSHISTFILE=/dev/null
unset HISTFILE

tmux_init()
{
    tmux new-session -d -s "arch" -n "root"
    tmux new-window -n "tmp1" -t "arch" -c /tmp
    tmux new-window -n "tmp2" -t "arch" -c /tmp
    tmux new-window -n "tmp3" -t "arch" -c /tmp
    tmux new-window -n "tmp4" -t "arch" -c /tmp
    tmux new-window -n "tmp5" -t "arch" -c /tmp
    tmux new-window -n "tmp6" -t "arch" -c /tmp
    tmux select-window -t "root"
    tmux attach-session -d
}

if whereis -b tmux 2>&1 >/dev/null; then
   [ -z "$TMUX" ] && (tmux attach-session -d -t "arch" || tmux_init)
fi
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
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo ArchLinux`
GRUB_CMDLINE_LINUX_DEFAULT="quiet ipv6.disable=1 module_blacklist=ipv6,nf_defrag_ipv6"
GRUB_CMDLINE_LINUX=""
EOF

mkdir -p ${mount_dir}/etc/mkinitcpio.d
cat << EOF > ${mount_dir}/etc/mkinitcpio.d/linux.preset
ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default')
default_image="/boot/initramfs-linux.img"

COMPRESSION="xz"
EOF

chroot ${mount_dir} /bin/bash -c "
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
echo root:$rootpwd | chpasswd
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
echo en_US.UTF-8 UTF-8 > /etc/locale.gen
locale-gen
echo LANG=en_US.UTF-8 > /etc/locale.conf
pacman -Sy linux grub --noconfirm --cachedir /tmp --ignore dhcpcd --ignore logrotate --ignore nano --ignore netctl --ignore usbutils --ignore vi --ignore s-nail

grub-install --force $dev
grub-mkconfig -o /boot/grub/grub.cfg

systemctl enable systemd-networkd systemd-resolved systemd-timesyncd sshd v2ray
sleep 2
rm -rf /var/log/* /usr/share/doc/* /usr/share/man/* /tmp/* /var/tmp/* /root/.cache/* /var/cache/pacman/* /var/lib/pacman/sync/*
find /usr/lib/python* /usr/local/lib/python* /usr/share/python* -type d -name __pycache__ -exec rm -rf {} \; -prune
find /usr/lib/python* /usr/local/lib/python* /usr/share/python* -type f -name *.py[co] -exec rm -rf {} \;
find /usr/share/locale -maxdepth 1 ! -name 'en' -exec rm -rf {} \; -prune
"

umount ${mount_dir}/{dev,proc,sys,tmp,}
sleep 1

echo Done.
echo ===================================================
echo "Root  PASS: $rootpwd"
echo "V2Ray UUID: $UUID"
echo ===================================================
