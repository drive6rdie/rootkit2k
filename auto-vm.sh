#!/bin/bash
# Build your kernel before running this script

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_bzImage>"
    exit 1
fi

KERNEL_PATH="$1"

DISK_IMG="disk.img"
DISK_SIZE="450M"
ROOTFS_DIR="/tmp/my-rootfs"
LOOP_DEVICE=""

# Check if disk image exists
if [ ! -f "$DISK_IMG" ]; then
    echo "Creating disk image..."
    truncate -s $DISK_SIZE $DISK_IMG

    echo "Creating partition table..."
    /sbin/parted -s $DISK_IMG mktable msdos
    /sbin/parted -s $DISK_IMG mkpart primary ext4 1 "100%"
    /sbin/parted -s $DISK_IMG set 1 boot on
else
    echo "Disk image '$DISK_IMG' already exists. Skipping disk creation steps."
fi

# Set up a new loop device and force the use of a free one
echo "Setting up loop device..."
LOOP_DEVICE=$(sudo losetup -f --show $DISK_IMG)
if [ -z "$LOOP_DEVICE" ]; then
    echo "Error: Could not create a loop device."
    exit 1
fi
echo "Loop device set up as $LOOP_DEVICE."

# Re-read the partition table
sudo partprobe $LOOP_DEVICE

# Check if the partition is accessible and valid
if [ ! -e ${LOOP_DEVICE}p1 ]; then
    echo "Error: Partition not found. Re-reading partition table..."
    sudo partx -u ${LOOP_DEVICE}
fi

# Check the filesystem integrity and reformat if necessary
if ! sudo fsck.ext4 -fn ${LOOP_DEVICE}p1; then
    echo "Filesystem corrupted. Reformatting partition as ext4..."
    sudo mkfs.ext4 ${LOOP_DEVICE}p1
fi

# Mount partition if not already mounted
if ! mountpoint -q $ROOTFS_DIR; then
    echo "Mounting partition..."
    mkdir -p $ROOTFS_DIR
    sudo mount ${LOOP_DEVICE}p1 $ROOTFS_DIR
else
    echo "Partition already mounted at '$ROOTFS_DIR'."
fi

# Check if root filesystem is populated
if [ ! -d "$ROOTFS_DIR/bin" ]; then
    echo "Installing minimal Alpine Linux..."
    sudo docker run -it --rm -v $ROOTFS_DIR:/my-rootfs alpine sh -c '
      apk add openrc util-linux build-base python3;
      ln -s agetty /etc/init.d/agetty.ttyS0;
      echo ttyS0 > /etc/securetty;
      rc-update add agetty.ttyS0 default;
      rc-update add root default;
      echo "root:password" | chpasswd;
      rc-update add devfs boot;
      rc-update add procfs boot;
      rc-update add sysfs boot;
      for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /my-rootfs; done;
      for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done;
    '
else
    echo "Root filesystem already populated. Skipping Alpine Linux installation."
fi

echo "Installing GRUB and Kernel..."
sudo mkdir -p $ROOTFS_DIR/boot/grub
sudo cp $KERNEL_PATH $ROOTFS_DIR/boot/vmlinuz

cat <<EOF | sudo tee $ROOTFS_DIR/boot/grub/grub.cfg
serial
terminal_input serial
terminal_output serial
set root=(hd0,1)
menuentry "Linux2600" {
    linux /boot/vmlinuz root=/dev/sda1 console=ttyS0 noapic
}
EOF

sudo grub-install --directory=/usr/lib/grub/i386-pc --boot-directory=$ROOTFS_DIR/boot $LOOP_DEVICE

echo "Cleaning up..."
sudo umount $ROOTFS_DIR
sudo losetup -d $LOOP_DEVICE

echo "Running QEMU..."
qemu-system-x86_64 -hda $DISK_IMG -nographic
